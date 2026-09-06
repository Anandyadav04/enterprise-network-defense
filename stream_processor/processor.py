"""
stream_processor/processor.py
──────────────────────────────
Real-time stream processing service.

Consumes from Kafka topics:
  - raw-alerts    (Suricata alerts)
  - raw-flows     (Flow generator flows)

Responsibilities:
  1. Filter low-confidence / noise events
  2. Correlate Suricata alerts with their matching flow features
  3. Aggregate related events by source IP within a time window
  4. Compute behavioral anomaly scores (port scan, brute-force, etc.)
  5. Publish enriched, correlated events to `enriched-events` topic

This is the critical gate between raw detection and AI inference.
Only suspicious events should reach the AI layer.
"""

import json
import logging
import time
import uuid
from collections import defaultdict
from typing import Optional

from kafka import KafkaConsumer, KafkaProducer

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP = "kafka:9092"
INPUT_TOPICS = ["raw-alerts", "raw-flows"]
OUTPUT_TOPIC = "enriched-events"

# Correlation window: events from same src_ip within this window are linked
CORRELATION_WINDOW_SECONDS = 60

# Minimum Suricata severity to forward for AI analysis (1=highest, 3=lowest)
MIN_SURICATA_SEVERITY = 3

# Thresholds for behavioral anomaly detection
PORT_SCAN_THRESHOLD = 15        # distinct dst_ports from same src in window
BRUTE_FORCE_THRESHOLD = 10      # repeated connections to same dst_port


class StreamProcessor:
    """
    Event correlation and enrichment service.
    Maintains a rolling time-window of recent events per source IP
    for behavioral analysis.
    """

    def __init__(
        self,
        bootstrap_servers: str = KAFKA_BOOTSTRAP,
        group_id: str = "stream-processor-group",
    ):
        self.consumer = KafkaConsumer(
            *INPUT_TOPICS,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            auto_offset_reset="latest",
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )
        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )

        # In-memory rolling window: src_ip → list of recent event dicts
        # In production, this would be backed by Redis for multi-instance support
        self._ip_window: dict = defaultdict(list)
        self._flow_buffer: dict = {}  # flow_key → flow dict

    def run(self) -> None:
        """Main processing loop."""
        logger.info("StreamProcessor started. Consuming from: %s", INPUT_TOPICS)
        for msg in self.consumer:
            event = msg.value
            topic = msg.topic

            if topic == "raw-flows":
                self._buffer_flow(event)
            elif topic == "raw-alerts":
                self._process_alert(event)

    def _buffer_flow(self, flow: dict) -> None:
        """Buffer flow features for correlation with alerts."""
        key = self._flow_key(flow)
        if key:
            self._flow_buffer[key] = flow

    def _process_alert(self, alert: dict) -> None:
        """Correlate an alert with flow data and compute anomaly scores."""
        src_ip = alert.get("src_ip", "")
        dst_ip = alert.get("dst_ip", "")

        # Filter by severity
        severity = alert.get("alert", {}).get("severity", 3) if "alert" in alert else 3
        if severity > MIN_SURICATA_SEVERITY and alert.get("event_type") == "alert":
            return  # Noise — skip

        # Track event in rolling window
        self._update_window(src_ip, alert)

        # Find matching flow features
        flow = self._find_flow(src_ip, dst_ip, alert)

        # Compute behavioral scores
        behavior_score = self._behavior_anomaly_score(src_ip)

        # Build enriched event
        enriched = {
            "event_id": str(uuid.uuid4()),
            "timestamp": alert.get("timestamp", ""),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": alert.get("src_port"),
            "dst_port": alert.get("dest_port"),
            "protocol": alert.get("proto", "UNKNOWN"),
            "suricata_signature": alert.get("alert", {}).get("signature"),
            "suricata_category": alert.get("alert", {}).get("category"),
            "suricata_severity": severity,
            "behavior_anomaly_score": behavior_score,
            "related_event_ids": self._related_event_ids(src_ip),
        }

        # Merge flow features if available
        if flow:
            enriched.update({
                "duration": flow.get("duration", 0.0),
                "packet_count": flow.get("packet_count", 0),
                "byte_count": flow.get("byte_count", 0),
                "fwd_packets": flow.get("fwd_packets", 0),
                "bwd_packets": flow.get("bwd_packets", 0),
                "fwd_bytes": flow.get("fwd_bytes", 0),
                "bwd_bytes": flow.get("bwd_bytes", 0),
                "iat_mean": flow.get("iat_mean", 0.0),
                "iat_std": flow.get("iat_std", 0.0),
                "dns_query_count": flow.get("dns_query_count", 0),
                "payload_entropy": flow.get("payload_entropy", 0.0),
            })

        self.producer.send(OUTPUT_TOPIC, value=enriched)
        logger.info("Enriched event published: %s [src=%s]", enriched["event_id"], src_ip)

    def _update_window(self, src_ip: str, event: dict) -> None:
        """Add event to rolling window; evict entries older than window."""
        now = time.time()
        self._ip_window[src_ip].append({"time": now, "event": event})
        # Evict old entries
        self._ip_window[src_ip] = [
            e for e in self._ip_window[src_ip]
            if now - e["time"] < CORRELATION_WINDOW_SECONDS
        ]

    def _behavior_anomaly_score(self, src_ip: str) -> float:
        """
        Compute a 0.0–1.0 behavioral anomaly score from the rolling window.
        Detects port scanning and connection flooding patterns.
        """
        entries = self._ip_window.get(src_ip, [])
        if not entries:
            return 0.0

        dst_ports = set()
        dst_port_counts: dict = defaultdict(int)
        for e in entries:
            ev = e["event"]
            dp = ev.get("dst_port") or ev.get("dest_port")
            if dp:
                dst_ports.add(dp)
                dst_port_counts[dp] += 1

        port_scan_score = min(len(dst_ports) / PORT_SCAN_THRESHOLD, 1.0)
        brute_force_score = min(
            max(dst_port_counts.values(), default=0) / BRUTE_FORCE_THRESHOLD, 1.0
        )

        return round(max(port_scan_score, brute_force_score), 3)

    def _related_event_ids(self, src_ip: str) -> list:
        """Return event IDs from the same src_ip in the current window."""
        return [
            e["event"].get("event_id", "")
            for e in self._ip_window.get(src_ip, [])
            if e["event"].get("event_id")
        ]

    def _find_flow(self, src_ip: str, dst_ip: str, alert: dict) -> Optional[dict]:
        """Try to find buffered flow features matching this alert."""
        dst_port = alert.get("dest_port") or alert.get("dst_port")
        src_port = alert.get("src_port")
        proto = alert.get("proto", "TCP")
        key = f"{src_ip}|{dst_ip}|{src_port}|{dst_port}|{proto}"
        return self._flow_buffer.get(key)

    @staticmethod
    def _flow_key(flow: dict) -> Optional[str]:
        try:
            return "|".join([
                flow["src_ip"], flow["dst_ip"],
                str(flow.get("src_port", 0)),
                str(flow.get("dst_port", 0)),
                flow["protocol"],
            ])
        except KeyError:
            return None
