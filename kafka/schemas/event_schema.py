"""
kafka/schemas/event_schema.py
──────────────────────────────
Canonical JSON schemas and Pydantic models for all Kafka topic messages.

Topics:
  raw-flows       → FlowEvent       (from packet_engine flow_generator)
  raw-alerts      → SuricataAlert   (from Suricata eve_reader)
  enriched-events → EnrichedEvent   (from stream_processor)
  scored-events   → ScoredEvent     (from risk_engine + threat_intel)

These schemas define the contract between pipeline stages.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class FlowEvent(BaseModel):
    """Network flow emitted by the flow_generator after aggregation."""
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    start_time: float
    duration: float
    packet_count: int
    byte_count: int
    fwd_packets: int
    fwd_bytes: int
    bwd_packets: int
    bwd_bytes: int
    iat_mean: float = 0.0
    iat_std: float = 0.0
    dns_query_count: int = 0
    dns_queries: List[str] = Field(default_factory=list)
    tcp_flags_seen: List[str] = Field(default_factory=list)
    payload_entropy: float = 0.0
    source: str = "flow_generator"


class SuricataAlert(BaseModel):
    """IDS alert from Suricata EVE JSON output."""
    timestamp: str
    event_type: str                      # "alert", "dns", "flow", "http"
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    alert: Optional[dict] = None         # Contains signature, category, severity
    dns: Optional[dict] = None
    http: Optional[dict] = None
    flow: Optional[dict] = None
    source: str = "suricata"


class EnrichedEvent(BaseModel):
    """
    Stream-processed event: correlated Suricata alert + flow features.
    Published to the `enriched-events` topic for AI inference.
    """
    event_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    # Suricata fields
    suricata_signature: Optional[str] = None
    suricata_category: Optional[str] = None
    suricata_severity: Optional[int] = None
    # Aggregated flow features (for AI)
    duration: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    iat_mean: float = 0.0
    iat_std: float = 0.0
    dns_query_count: int = 0
    payload_entropy: float = 0.0
    behavior_anomaly_score: float = 0.0
    related_event_ids: List[str] = Field(default_factory=list)


class ScoredEvent(BaseModel):
    """
    Final scored event: AI classification + TI enrichment + risk score.
    Published to `scored-events` topic for Logstash → Elasticsearch.
    """
    event_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    # Suricata
    suricata_signature: Optional[str] = None
    suricata_category: Optional[str] = None
    suricata_severity: Optional[int] = None
    # AI inference
    ai_attack_class: str = "BENIGN"
    ai_confidence: float = 0.0
    ai_top_classes: Optional[dict] = None
    # Threat Intelligence
    ti_abuseipdb_score: Optional[float] = None
    ti_otx_pulse_count: Optional[int] = None
    ti_country: Optional[str] = None
    ti_isp: Optional[str] = None
    # Risk
    risk_score: float = 0.0
    risk_tier: str = "LOW"
    # Asset
    asset_criticality: float = 0.5
    asset_name: Optional[str] = None
