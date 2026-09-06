"""
threat_intel/enricher.py
─────────────────────────
Threat Intelligence enrichment service.

Consumes: enriched-events (after AI inference adds attack_class + confidence)
Enriches: AbuseIPDB IP reputation + AlienVault OTX IOC lookups
Publishes: scored-events (to risk engine and Logstash)

APIs Used:
  - AbuseIPDB v2: https://docs.abuseipdb.com/#check-endpoint
  - AlienVault OTX: https://otx.alienvault.com/api

Rate limiting:
  - AbuseIPDB free tier: 1000 requests/day
  - OTX free tier: generous, but cache results in Redis (TTL: 1 hour)
"""

import json
import logging
import os
import time
from typing import Optional

import redis
import requests
from kafka import KafkaConsumer, KafkaProducer

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
INPUT_TOPIC = "enriched-events"
OUTPUT_TOPIC = "scored-events"

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
OTX_BASE = "https://otx.alienvault.com/api/v1"

TI_CACHE_TTL = 3600  # Cache TI results for 1 hour


class ThreatIntelEnricher:
    """
    Enriches security events with external Threat Intelligence.
    Results are cached in Redis to minimise API calls.
    """

    def __init__(self, redis_host: str = "redis", redis_port: int = 6379):
        self.consumer = KafkaConsumer(
            INPUT_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP,
            group_id="threat-intel-group",
            auto_offset_reset="latest",
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )
        self.producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )
        self._redis = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)

    def run(self) -> None:
        """Main enrichment loop."""
        logger.info("ThreatIntelEnricher started — consuming from %s", INPUT_TOPIC)
        for msg in self.consumer:
            event = msg.value
            src_ip = event.get("src_ip", "")

            # Enrich with TI data
            ti = self._get_ti(src_ip)
            event.update(ti)

            # Forward to scored-events for Logstash → ES
            self.producer.send(OUTPUT_TOPIC, value=event)

    def _get_ti(self, ip: str) -> dict:
        """Return cached or freshly fetched TI data for an IP."""
        cache_key = f"ti:{ip}"
        cached = self._redis.get(cache_key)
        if cached:
            return json.loads(cached)

        ti_data = {}
        ti_data.update(self._abuseipdb_check(ip))
        ti_data.update(self._otx_check(ip))

        self._redis.setex(cache_key, TI_CACHE_TTL, json.dumps(ti_data))
        return ti_data

    def _abuseipdb_check(self, ip: str) -> dict:
        """Query AbuseIPDB for IP reputation score."""
        if not ABUSEIPDB_API_KEY:
            return {}
        try:
            resp = requests.get(
                f"{ABUSEIPDB_BASE}/check",
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0) / 100.0  # Normalise to 0–1
            return {
                "ti_abuseipdb_score": round(abuse_score, 3),
                "ti_country": data.get("countryCode"),
                "ti_isp": data.get("isp"),
                "ti_domain": data.get("domain"),
                "ti_total_reports": data.get("totalReports", 0),
            }
        except Exception as exc:
            logger.warning("AbuseIPDB query failed for %s: %s", ip, exc)
            return {"ti_abuseipdb_score": 0.0}

    def _otx_check(self, ip: str) -> dict:
        """Query AlienVault OTX for IOC pulse matches."""
        if not OTX_API_KEY:
            return {}
        try:
            resp = requests.get(
                f"{OTX_BASE}/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": OTX_API_KEY},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            return {
                "ti_otx_pulse_count": pulse_count,
                "ti_otx_malicious": pulse_count > 0,
            }
        except Exception as exc:
            logger.warning("OTX query failed for %s: %s", ip, exc)
            return {"ti_otx_pulse_count": 0, "ti_otx_malicious": False}

    @staticmethod
    def _composite_ti_score(ti: dict) -> float:
        """
        Combine AbuseIPDB and OTX signals into a single 0.0–1.0 TI score.
        """
        abuse = ti.get("ti_abuseipdb_score", 0.0)
        otx_hit = 1.0 if ti.get("ti_otx_malicious") else 0.0
        return round((abuse * 0.6) + (otx_hit * 0.4), 3)
