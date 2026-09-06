"""
backend/app/api/dashboard.py
─────────────────────────────
Dashboard summary API — aggregated metrics for Kibana-equivalent
display in any custom SOC frontend.
"""

from fastapi import APIRouter
router = APIRouter(prefix="/dashboard")


@router.get("/summary")
async def summary():
    """
    Return high-level SOC dashboard metrics:
    - Total events (last 24h)
    - Events by risk tier
    - Top attacking IPs
    - Top attack classes
    - Detection timeline (hourly buckets)
    TODO: Implement using Elasticsearch aggregations.
    """
    return {
        "total_events_24h": 0,
        "by_risk_tier": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
        "top_src_ips": [],
        "top_attack_classes": [],
        "hourly_timeline": [],
    }
