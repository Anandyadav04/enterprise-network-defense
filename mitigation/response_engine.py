"""
mitigation/response_engine.py
──────────────────────────────
Response Engine — consumes scored-events from Kafka and applies
the appropriate response action based on the risk tier.

Response Tiers:
  LOW      → Log only (already in Elasticsearch)
  MEDIUM   → Kibana dashboard alert marker
  HIGH     → Email + Slack notification to SOC team
  CRITICAL → Incident report + optional IPS block (pfSense API)

Key design principle:
  A single AI prediction NEVER directly triggers blocking.
  Only events with risk_score > 76 AND risk_tier == CRITICAL
  AND IPS_ENABLED == true can trigger automated blocking.
"""

import json
import logging
import os
import smtplib
import uuid
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Optional

import requests
from kafka import KafkaConsumer

from mitigation.ips_client import IPSClient

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
INPUT_TOPIC = "scored-events"

IPS_ENABLED = os.getenv("IPS_ENABLED", "false").lower() == "true"
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ALERT_EMAIL = os.getenv("ALERT_EMAIL_RECIPIENT", "")


class ResponseEngine:
    """
    Consumes scored security events and applies tiered response actions.
    """

    def __init__(self):
        self.consumer = KafkaConsumer(
            INPUT_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP,
            group_id="response-engine-group",
            auto_offset_reset="latest",
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )
        self.ips = IPSClient() if IPS_ENABLED else None

    def run(self) -> None:
        """Main response loop."""
        logger.info("ResponseEngine started. IPS_ENABLED=%s", IPS_ENABLED)
        for msg in self.consumer:
            event = msg.value
            tier = event.get("risk_tier", "LOW")
            score = event.get("risk_score", 0.0)
            src_ip = event.get("src_ip", "unknown")

            logger.info("Response: tier=%s score=%.1f src=%s", tier, score, src_ip)

            if tier == "LOW":
                self._handle_low(event)
            elif tier == "MEDIUM":
                self._handle_medium(event)
            elif tier == "HIGH":
                self._handle_high(event)
            elif tier == "CRITICAL":
                self._handle_critical(event)

    def _handle_low(self, event: dict) -> None:
        """Low — already logged in Elasticsearch. No additional action."""
        pass

    def _handle_medium(self, event: dict) -> None:
        """Medium — log enhanced alert marker for Kibana dashboard."""
        logger.warning(
            "[MEDIUM ALERT] src=%s attack=%s score=%.1f",
            event.get("src_ip"), event.get("ai_attack_class"), event.get("risk_score"),
        )

    def _handle_high(self, event: dict) -> None:
        """High — send email and Slack notification."""
        subject = f"[HIGH THREAT] {event.get('ai_attack_class')} from {event.get('src_ip')}"
        body = self._format_alert_body(event)
        self._send_email(subject, body)
        self._send_slack(f":warning: *HIGH THREAT DETECTED*\n{body}")

    def _handle_critical(self, event: dict) -> None:
        """Critical — generate incident report and optionally block via IPS."""
        subject = f"[CRITICAL] {event.get('ai_attack_class')} from {event.get('src_ip')}"
        body = self._format_alert_body(event)
        report_path = self._generate_incident_report(event)

        self._send_email(subject, body)
        self._send_slack(f":rotating_light: *CRITICAL THREAT*\n{body}\nReport: `{report_path}`")

        if IPS_ENABLED and self.ips:
            logger.critical(
                "IPS: Requesting block for src=%s (score=%.1f)",
                event.get("src_ip"), event.get("risk_score"),
            )
            self.ips.block_ip(event.get("src_ip"), duration_minutes=60)

    def _format_alert_body(self, event: dict) -> str:
        return (
            f"Event ID:      {event.get('event_id', 'N/A')}\n"
            f"Timestamp:     {event.get('timestamp', 'N/A')}\n"
            f"Source IP:     {event.get('src_ip', 'N/A')}\n"
            f"Destination:   {event.get('dst_ip', 'N/A')}\n"
            f"Risk Score:    {event.get('risk_score', 0.0):.1f} / 100\n"
            f"Risk Tier:     {event.get('risk_tier', 'N/A')}\n"
            f"Attack Class:  {event.get('ai_attack_class', 'N/A')}\n"
            f"AI Confidence: {event.get('ai_confidence', 0.0) * 100:.1f}%\n"
            f"Suricata:      {event.get('suricata_signature', 'N/A')}\n"
            f"TI Score:      AbuseIPDB={event.get('ti_abuseipdb_score', 'N/A')} "
            f"OTX={event.get('ti_otx_pulse_count', 'N/A')} pulses\n"
        )

    def _generate_incident_report(self, event: dict) -> str:
        """Write a structured incident report to disk."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_id = str(uuid.uuid4())[:8]
        path = f"/tmp/incident_{ts}_{report_id}.md"
        content = f"# Incident Report\n\n**Generated:** {ts}\n\n```\n{self._format_alert_body(event)}\n```\n"
        try:
            with open(path, "w") as f:
                f.write(content)
            logger.info("Incident report written: %s", path)
        except Exception as exc:
            logger.error("Failed to write incident report: %s", exc)
        return path

    def _send_email(self, subject: str, body: str) -> None:
        if not all([SMTP_HOST, SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL]):
            return
        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = SMTP_USER
            msg["To"] = ALERT_EMAIL
            msg.set_content(body)
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASSWORD)
                s.send_message(msg)
            logger.info("Email alert sent to %s", ALERT_EMAIL)
        except Exception as exc:
            logger.error("Email send failed: %s", exc)

    def _send_slack(self, text: str) -> None:
        if not SLACK_WEBHOOK:
            return
        try:
            requests.post(SLACK_WEBHOOK, json={"text": text}, timeout=5)
        except Exception as exc:
            logger.error("Slack notification failed: %s", exc)
