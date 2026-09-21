"""
backend/app/api/alerts.py
──────────────────────────
REST API endpoints for security alert management.
Primary source of truth: PostgreSQL alerts table (permanent threat store).
Fallback/telemetry: Elasticsearch security-events-* (strictly filtering out BENIGN flows).
"""

import logging
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession
import requests

from app.core.config import settings
from app.core.database import get_db, AsyncSessionLocal
from app.models.alert import Alert

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts")

ELASTICSEARCH_URL = settings.ELASTICSEARCH_URL or "http://elasticsearch:9200"


class AlertSummary(BaseModel):
    event_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    risk_tier: str
    risk_score: float
    ai_attack_class: str
    suricata_signature: Optional[str] = None
    status: str = "OPEN"   # OPEN | ACKNOWLEDGED | CLOSED
    analyst_note: Optional[str] = None


class AlertUpdateRequest(BaseModel):
    status: str  # ACKNOWLEDGED | CLOSED
    analyst_note: Optional[str] = None


@router.get("/", response_model=List[AlertSummary])
async def list_alerts(
    risk_tier: Optional[str] = Query(None, description="Filter by tier: LOW/MEDIUM/HIGH/CRITICAL"),
    status: Optional[str] = Query(None, description="Filter by status: OPEN/ACKNOWLEDGED/CLOSED"),
    limit: int = Query(1000, le=5000),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    """
    List security alerts with optional filtering.
    Always returns actual detected threats (excludes BENIGN flows).
    Sorted by timestamp descending.
    """
    # ── 1. Primary Store: PostgreSQL ──
    try:
        query = select(Alert).where(Alert.ai_attack_class != "BENIGN")
        if risk_tier:
            query = query.where(Alert.risk_tier == risk_tier.upper())
        if status:
            query = query.where(Alert.status == status.upper())

        query = query.order_by(Alert.timestamp.desc()).offset(offset).limit(limit)
        result = await db.execute(query)
        db_alerts = result.scalars().all()

        if db_alerts:
            return [
                AlertSummary(
                    event_id=a.event_id,
                    timestamp=a.timestamp.isoformat() if a.timestamp else "",
                    src_ip=a.src_ip,
                    dst_ip=a.dst_ip,
                    risk_tier=a.risk_tier,
                    risk_score=a.risk_score,
                    ai_attack_class=a.ai_attack_class,
                    suricata_signature=a.suricata_signature,
                    status=a.status,
                    analyst_note=a.analyst_note,
                )
                for a in db_alerts
            ]
    except Exception as e:
        logger.error("Error querying PostgreSQL alerts: %s", e)

    # ── 2. Fallback: Elasticsearch (Strictly Non-Benign Threats Only) ──
    try:
        must_not = [{"term": {"ai_attack_class.keyword": "BENIGN"}}]
        must = []
        if status:
            must.append({"term": {"status.keyword": status.upper()}})

        es_query = {
            "size": limit,
            "from": offset,
            "query": {
                "bool": {
                    "must": must,
                    "must_not": must_not
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        res = requests.post(
            f"{ELASTICSEARCH_URL}/security-events-*/_search",
            json=es_query,
            timeout=5
        )
        res.raise_for_status()
        data = res.json()

        alerts = []
        for hit in data.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            confidence = float(src.get("ai_confidence", 0.0))
            score = float(src.get("risk_score", confidence * 100))
            score = round(score, 2)

            if score >= 90:
                tier = "CRITICAL"
            elif score >= 75:
                tier = "HIGH"
            elif score >= 50:
                tier = "MEDIUM"
            else:
                tier = "LOW"

            if risk_tier and tier != risk_tier.upper():
                continue

            alerts.append(AlertSummary(
                event_id=src.get("event_id", hit.get("_id", "unknown")),
                timestamp=src.get("@timestamp", ""),
                src_ip=src.get("src_ip", "Unknown"),
                dst_ip=src.get("dst_ip", src.get("dest_ip", "Unknown")),
                risk_tier=tier,
                risk_score=score,
                ai_attack_class=src.get("ai_attack_class", "UNKNOWN"),
                suricata_signature=src.get("suricata_signature"),
                status=src.get("status", "OPEN"),
            ))

        return alerts
    except Exception as e:
        logger.error("Error querying Elasticsearch fallback: %s", e)
        return []


@router.get("/critical-count", response_model=int)
async def critical_open_count(db: AsyncSession = Depends(get_db)):
    """Count open CRITICAL alerts in the permanent database store."""
    try:
        stmt = select(func.count(Alert.id)).where(
            Alert.risk_tier == "CRITICAL",
            Alert.status == "OPEN",
            Alert.ai_attack_class != "BENIGN"
        )
        result = await db.execute(stmt)
        return result.scalar_one() or 0
    except Exception as e:
        logger.error("Error counting critical alerts from DB: %s", e)

    # Fallback to Elasticsearch
    try:
        es_query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"ai_confidence": {"gte": 0.90}}},
                        {"term": {"status.keyword": "OPEN"}}
                    ],
                    "must_not": [
                        {"term": {"ai_attack_class.keyword": "BENIGN"}}
                    ]
                }
            }
        }
        res = requests.post(f"{ELASTICSEARCH_URL}/security-events-*/_search", json=es_query, timeout=5)
        res.raise_for_status()
        return res.json().get("hits", {}).get("total", {}).get("value", 0)
    except Exception as e:
        logger.error("Error counting critical alerts from ES: %s", e)
        return 0


@router.get("/{event_id}", response_model=AlertSummary)
async def get_alert(event_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve a single alert by event ID."""
    stmt = select(Alert).where(Alert.event_id == event_id)
    res = await db.execute(stmt)
    a = res.scalar_one_or_none()
    if a:
        return AlertSummary(
            event_id=a.event_id,
            timestamp=a.timestamp.isoformat() if a.timestamp else "",
            src_ip=a.src_ip,
            dst_ip=a.dst_ip,
            risk_tier=a.risk_tier,
            risk_score=a.risk_score,
            ai_attack_class=a.ai_attack_class,
            suricata_signature=a.suricata_signature,
            status=a.status,
            analyst_note=a.analyst_note,
        )

    raise HTTPException(status_code=404, detail="Alert not found")


@router.patch("/{event_id}")
async def update_alert_status(
    event_id: str,
    body: AlertUpdateRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Acknowledge or close an alert. Optionally add analyst notes.
    Updates PostgreSQL persistent record and syncs to Elasticsearch.
    """
    if body.status not in ("OPEN", "ACKNOWLEDGED", "CLOSED"):
        raise HTTPException(status_code=400, detail="Invalid status value")

    now = datetime.utcnow()
    update_vals = {
        "status": body.status,
        "updated_at": now,
    }
    if body.analyst_note is not None:
        update_vals["analyst_note"] = body.analyst_note
    if body.status == "ACKNOWLEDGED":
        update_vals["acknowledged_at"] = now
    elif body.status == "CLOSED":
        update_vals["closed_at"] = now

    # 1. Update PostgreSQL
    stmt = (
        update(Alert)
        .where(Alert.event_id == event_id)
        .values(**update_vals)
    )
    result = await db.execute(stmt)
    await db.commit()

    # 2. Sync to Elasticsearch (best effort)
    try:
        es_update = {
            "query": {"match": {"event_id": event_id}},
            "script": {
                "source": f"ctx._source.status = '{body.status}'",
                "lang": "painless"
            }
        }
        requests.post(
            f"{ELASTICSEARCH_URL}/security-events-*/_update_by_query",
            json=es_update,
            timeout=5
        )
    except Exception as e:
        logger.warning("Failed to sync status update to Elasticsearch: %s", e)

    return {"event_id": event_id, "status": body.status, "updated": True}


@router.get("/stats/summary")
async def alert_stats(db: AsyncSession = Depends(get_db)):
    """Return alert counts grouped by risk tier and status."""
    try:
        total = await db.execute(select(func.count(Alert.id)).where(Alert.ai_attack_class != "BENIGN"))
        
        tier_counts = {}
        for tier in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            res = await db.execute(select(func.count(Alert.id)).where(Alert.risk_tier == tier, Alert.ai_attack_class != "BENIGN"))
            tier_counts[tier] = res.scalar_one() or 0

        status_counts = {}
        for st in ["OPEN", "ACKNOWLEDGED", "CLOSED"]:
            res = await db.execute(select(func.count(Alert.id)).where(Alert.status == st, Alert.ai_attack_class != "BENIGN"))
            status_counts[st] = res.scalar_one() or 0

        return {
            "total": total.scalar_one() or 0,
            "by_tier": tier_counts,
            "by_status": status_counts,
        }
    except Exception as e:
        logger.error("Error computing alert stats: %s", e)
        return {
            "total": 0,
            "by_tier": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "by_status": {"OPEN": 0, "ACKNOWLEDGED": 0, "CLOSED": 0},
        }
