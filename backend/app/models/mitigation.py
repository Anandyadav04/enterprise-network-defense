"""
backend/app/models/mitigation.py
────────────────────────────────
SQLAlchemy ORM model for persisting Active IPS Block Rules and Firewall Mitigations.

Tracks automated blocks triggered by CRITICAL AI risk scores as well as
manual blocks executed by SOC analysts via pfSense REST API or local firewall.
"""

from datetime import datetime
from sqlalchemy import String, Float, DateTime, Text, Integer
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    event_id: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    threat_class: Mapped[str] = mapped_column(String(32), default="MANUAL_INTERVENTION")
    risk_score: Mapped[float] = mapped_column(Float, default=100.0)
    action: Mapped[str] = mapped_column(String(16), default="BLOCK")  # BLOCK | RATE_LIMIT | QUARANTINE
    firewall_target: Mapped[str] = mapped_column(String(64), default="pfSense WAN (192.168.1.1)")
    rule_name: Mapped[str] = mapped_column(String(128))
    rule_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    interface: Mapped[str] = mapped_column(String(16), default="WAN")
    duration_minutes: Mapped[int] = mapped_column(Integer, default=60)
    status: Mapped[str] = mapped_column(String(24), default="ACTIVE", index=True)  # ACTIVE | UNBLOCKED | EXPIRED
    mitigation_mode: Mapped[str] = mapped_column(String(16), default="AUTOMATED")  # AUTOMATED | MANUAL
    incident_report_path: Mapped[str] = mapped_column(String(255), nullable=True)
    analyst_notes: Mapped[str] = mapped_column(Text, nullable=True)
    blocked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    unblocked_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
