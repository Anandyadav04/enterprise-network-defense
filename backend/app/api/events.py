"""
backend/app/api/events.py
──────────────────────────
REST API endpoints for querying security events from Elasticsearch.
"""

from fastapi import APIRouter, Query
from typing import Optional

router = APIRouter(prefix="/events")


@router.get("/")
async def list_events(
    src_ip: Optional[str] = Query(None),
    attack_class: Optional[str] = Query(None),
    risk_tier: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
):
    """
    Query security events from Elasticsearch.
    Supports filtering by source IP, attack class, and risk tier.
    TODO: Implement Elasticsearch query via elasticsearch-py client.
    """
    # Stub — replace with ES query
    return {"events": [], "total": 0}


@router.get("/{event_id}")
async def get_event(event_id: str):
    """Retrieve a full event record from Elasticsearch by ID."""
    # Stub — replace with ES get by ID
    return {"event_id": event_id, "detail": "Not yet implemented"}
