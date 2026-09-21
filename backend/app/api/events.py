"""
backend/app/api/events.py
──────────────────────────
REST API endpoints for querying live network flow events from Elasticsearch.
Serves full telemetry (benign flows + flagged flows) to the Network Flows monitor.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Query
import requests

from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/events")

ELASTICSEARCH_URL = settings.ELASTICSEARCH_URL or "http://elasticsearch:9200"


@router.get("/")
async def list_events(
    src_ip: Optional[str] = Query(None),
    proto: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
):
    """
    Query live network flow events from Elasticsearch.
    Returns both benign and flagged flows for the Network Flows telemetry monitor.
    """
    try:
        must = []
        if src_ip:
            must.append({"term": {"src_ip.keyword": src_ip}})
        if proto and proto.upper() != "ALL":
            must.append({"term": {"protocol.keyword": proto.upper()}})

        query = {
            "size": limit,
            "from": offset,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        if must:
            query["query"] = {"bool": {"must": must}}

        res = requests.post(
            f"{ELASTICSEARCH_URL}/security-events-*/_search",
            json=query,
            timeout=5
        )
        res.raise_for_status()
        data = res.json()

        hits = data.get("hits", {}).get("hits", [])
        total = data.get("hits", {}).get("total", {}).get("value", len(hits))

        flows = []
        for h in hits:
            src = h.get("_source", {})
            event_id = src.get("event_id") or h.get("_id")
            attack_class = src.get("ai_attack_class", "BENIGN")
            is_attack = attack_class != "BENIGN" or src.get("suricata_signature")

            bytes_val = int(src.get("byte_count") or src.get("bytes") or src.get("fwd_bytes", 0) + src.get("bwd_bytes", 0) or 512)
            pkts_val = int(src.get("packet_count") or src.get("pkts") or src.get("fwd_packets", 0) + src.get("bwd_packets", 0) or 5)
            dur_val = float(src.get("duration") or 0.5)

            flows.append({
                "id": event_id,
                "timestamp": src.get("@timestamp") or src.get("timestamp"),
                "src": src.get("src_ip", "Unknown"),
                "dst": src.get("dst_ip") or src.get("dest_ip", "Unknown"),
                "sport": src.get("src_port", 0),
                "dport": src.get("dst_port") or src.get("dest_port", 0),
                "proto": (src.get("protocol") or "TCP").upper(),
                "bytes": bytes_val,
                "pkts": pkts_val,
                "dur": f"{dur_val:.2f}s",
                "status": "FLAGGED" if is_attack else "ACTIVE",
                "attack_class": attack_class if is_attack else None
            })

        return {"flows": flows, "total": total}
    except Exception as e:
        logger.error("Error querying events from ES: %s", e)
        return {"flows": [], "total": 0}
