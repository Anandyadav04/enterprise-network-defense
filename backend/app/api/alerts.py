"""
backend/app/api/alerts.py
──────────────────────────
REST API endpoints for security alert management.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

router = APIRouter(prefix="/alerts")


class AlertSummary(BaseModel):
    event_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    risk_tier: str
    risk_score: float
    ai_attack_class: str
    suricata_signature: Optional[str]
    status: str = "OPEN"   # OPEN | ACKNOWLEDGED | CLOSED


class AlertUpdateRequest(BaseModel):
    status: str  # ACKNOWLEDGED | CLOSED
    analyst_note: Optional[str] = None


@router.get("/", response_model=List[AlertSummary])
async def list_alerts(
    risk_tier: Optional[str] = Query(None, description="Filter by tier: LOW/MEDIUM/HIGH/CRITICAL"),
    status: Optional[str] = Query(None, description="Filter by status: OPEN/ACKNOWLEDGED/CLOSED"),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
):
    """
    List security alerts with optional filtering.
    Results are sorted by timestamp descending (most recent first).
    TODO: Query from PostgreSQL alert table.
    """
    # Stub — replace with DB query
    return []


@router.get("/{event_id}", response_model=AlertSummary)
async def get_alert(event_id: str):
    """Retrieve a single alert by event ID."""
    # Stub — replace with DB query
    raise HTTPException(status_code=404, detail="Alert not found")


@router.patch("/{event_id}")
async def update_alert_status(event_id: str, body: AlertUpdateRequest):
    """
    Acknowledge or close an alert. Optionally add analyst notes.
    Updates PostgreSQL record.
    """
    if body.status not in ("ACKNOWLEDGED", "CLOSED"):
        raise HTTPException(status_code=400, detail="Invalid status value")
    # Stub — replace with DB update
    return {"event_id": event_id, "status": body.status, "updated": True}


@router.get("/stats/summary")
async def alert_stats():
    """Return alert counts grouped by risk tier and status."""
    # Stub — replace with aggregation query
    return {
        "total": 0,
        "by_tier": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
        "by_status": {"OPEN": 0, "ACKNOWLEDGED": 0, "CLOSED": 0},
    }
