"""
backend/app/api/health.py — Health check endpoints
"""
from fastapi import APIRouter
import redis as redis_lib
from app.core.config import settings

router = APIRouter(prefix="/health")


@router.get("/")
async def health_check():
    """Basic health check — used by Docker Compose healthcheck."""
    return {"status": "ok", "service": "backend"}


@router.get("/redis")
async def redis_health():
    """Check Redis connectivity."""
    try:
        r = redis_lib.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT)
        r.ping()
        return {"status": "ok", "redis": f"{settings.REDIS_HOST}:{settings.REDIS_PORT}"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
