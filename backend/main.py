from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.api import alerts, events, health, dashboard
from app.core.config import settings
from app.core.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle handler."""
    await init_db()
    yield


app = FastAPI(
    title="Enterprise Network Defense API",
    description="REST API for the AI-Powered Network Threat Detection Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API Routers ───────────────────────────────────────────────────
app.include_router(health.router,     prefix="/api/v1", tags=["Health"])
app.include_router(alerts.router,     prefix="/api/v1", tags=["Alerts"])
app.include_router(events.router,     prefix="/api/v1", tags=["Events"])
app.include_router(dashboard.router,  prefix="/api/v1", tags=["Dashboard"])


@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "Enterprise Network Defense API",
        "version": "1.0.0",
        "docs": "/docs",
    }