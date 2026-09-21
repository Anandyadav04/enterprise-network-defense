"""
backend/app/services/alert_sync.py
───────────────────────────────────
Persistent Threat Recording Service.

Syncs and persists detected attacks (non-BENIGN events from AI classifier
and Suricata) into PostgreSQL's alerts table so attack records are permanently
stored, tracked, and never pushed out by high-volume background network flow.
"""

import asyncio
import logging
from datetime import datetime, timezone
import requests
from sqlalchemy import select
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.alert import Alert

logger = logging.getLogger(__name__)

ELASTICSEARCH_URL = settings.ELASTICSEARCH_URL or "http://elasticsearch:9200"


def determine_tier(score: float) -> str:
    if score >= 90:
        return "CRITICAL"
    elif score >= 75:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    return "LOW"


def parse_timestamp(ts_str: str) -> datetime:
    if not ts_str:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        # Handle ISO8601 strings
        clean_ts = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_ts).replace(tzinfo=None)
    except Exception:
        try:
            # Try parsing without microseconds if format differs
            return datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S")
        except Exception:
            return datetime.now(timezone.utc).replace(tzinfo=None)


async def sync_attacks_once(limit: int = 1000) -> int:
    """
    Fetch non-benign attacks from Elasticsearch and persist new ones into PostgreSQL.
    Returns the count of newly inserted alerts.
    """
    try:
        query = {
            "size": limit,
            "query": {
                "bool": {
                    "must_not": [
                        {"term": {"ai_attack_class.keyword": "BENIGN"}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        res = requests.post(
            f"{ELASTICSEARCH_URL}/security-events-*/_search",
            json=query,
            timeout=5
        )
        if not res.ok:
            return 0

        data = res.json()
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            return 0

        new_count = 0
        async with AsyncSessionLocal() as session:
            for hit in hits:
                src = hit.get("_source", {})
                event_id = src.get("event_id") or hit.get("_id")
                if not event_id:
                    continue

                src_ip = src.get("src_ip", "Unknown")
                sig = src.get("suricata_signature") or ""

                # Filter out internal orchestration/Docker Desktop IPs unless Suricata explicitly fired
                INTERNAL_IP_PREFIXES = ("192.168.65.", "192.168.64.", "172.17.", "172.18.", "172.19.", "172.20.", "127.", "::1")
                if any(str(src_ip).startswith(p) for p in INTERNAL_IP_PREFIXES) and not sig:
                    continue

                attack_class = src.get("ai_attack_class", "UNKNOWN")
                conf = float(src.get("ai_confidence", 0.0))
                score = float(src.get("risk_score", conf * 100))
                score = round(score, 2)
                tier = src.get("risk_tier") or determine_tier(score)
                ts = parse_timestamp(src.get("@timestamp") or src.get("timestamp"))

                new_alert = Alert(
                    event_id=event_id,
                    timestamp=ts,
                    src_ip=src.get("src_ip", "Unknown"),
                    dst_ip=src.get("dst_ip", src.get("dest_ip", "Unknown")),
                    risk_score=score,
                    risk_tier=tier.upper(),
                    ai_attack_class=attack_class,
                    suricata_signature=src.get("suricata_signature"),
                    status=src.get("status", "OPEN"),
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                session.add(new_alert)
                new_count += 1

            if new_count > 0:
                await session.commit()
                logger.info("Persisted %d new attack records to PostgreSQL", new_count)

        return new_count
    except Exception as e:
        logger.debug("sync_attacks_once error: %s", e)
        return 0


async def start_alert_sync_worker():
    """
    Background worker that runs continuously to guarantee all detected
    threats are saved to the persistent PostgreSQL record store.
    """
    logger.info("Starting alert persistence synchronization worker...")
    # Initial sync
    await sync_attacks_once(limit=3000)
    
    while True:
        try:
            await asyncio.sleep(4)
            await sync_attacks_once(limit=200)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Error in alert sync worker loop: %s", e)
            await asyncio.sleep(5)
