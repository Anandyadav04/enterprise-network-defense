"""
risk_engine/risk_scorer.py
──────────────────────────
Calculates a final numeric risk score (0–100) for each security
event by combining multiple evidence signals with configurable weights.

Risk Score Formula:
  Risk = (suricata_severity × W_IDS)
       + (ai_confidence    × W_AI)
       + (ti_score         × W_TI)
       + (asset_criticality× W_ASSET)
       + (behavior_anomaly × W_BEHAVIOR)

Weights are loaded from the response policy YAML (default: config/weights.yml).
"""

import logging
from dataclasses import dataclass, field
from typing import Literal

logger = logging.getLogger(__name__)

# Default weight configuration (must sum to 1.0)
DEFAULT_WEIGHTS = {
    "suricata": 0.30,
    "ai": 0.25,
    "threat_intel": 0.25,
    "asset_criticality": 0.10,
    "behavior": 0.10,
}

RiskTier = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class RiskInput:
    """All input signals required to compute a risk score."""

    # Suricata severity: 1 (informational) – 4 (critical), normalised to 0–1
    suricata_severity: float = 0.0      # Expected range 0.0–1.0 after normalisation

    # AI model confidence in a malicious classification (0.0–1.0)
    ai_confidence: float = 0.0

    # Threat Intelligence composite score (0.0–1.0)
    # Combines AbuseIPDB abuse score + OTX pulse hit weight
    ti_score: float = 0.0

    # Asset criticality of the target host (0.0–1.0)
    # Loaded from asset inventory; defaults to medium (0.5) if unknown
    asset_criticality: float = 0.5

    # Behavioral anomaly score from stream processor (0.0–1.0)
    behavior_anomaly: float = 0.0

    # Metadata (not used in scoring, passed through for correlation)
    src_ip: str = ""
    dst_ip: str = ""
    attack_class: str = "UNKNOWN"
    event_ids: list = field(default_factory=list)


@dataclass
class RiskResult:
    """Output of the risk scoring engine."""
    score: float            # 0.0 – 100.0
    tier: RiskTier
    weights_used: dict
    inputs: RiskInput


TIER_THRESHOLDS = [
    (76.0, "CRITICAL"),
    (51.0, "HIGH"),
    (26.0, "MEDIUM"),
    (0.0,  "LOW"),
]


class RiskScorer:
    """
    Weighted linear risk score calculator.
    Thread-safe — no mutable state after initialization.
    """

    def __init__(self, weights: dict = None):
        self.weights = weights or DEFAULT_WEIGHTS
        self._validate_weights()
        logger.info("RiskScorer initialized with weights: %s", self.weights)

    def score(self, inputs: RiskInput) -> RiskResult:
        """Compute a risk score and tier from the provided input signals."""
        raw = (
            inputs.suricata_severity  * self.weights["suricata"]
            + inputs.ai_confidence    * self.weights["ai"]
            + inputs.ti_score         * self.weights["threat_intel"]
            + inputs.asset_criticality* self.weights["asset_criticality"]
            + inputs.behavior_anomaly * self.weights["behavior"]
        )
        # Scale to 0–100
        final_score = round(min(max(raw * 100, 0.0), 100.0), 2)
        tier = self._tier(final_score)

        logger.debug(
            "Risk score: %.1f (%s) for src=%s attack=%s",
            final_score, tier, inputs.src_ip, inputs.attack_class,
        )

        return RiskResult(
            score=final_score,
            tier=tier,
            weights_used=self.weights.copy(),
            inputs=inputs,
        )

    @staticmethod
    def _tier(score: float) -> RiskTier:
        for threshold, tier in TIER_THRESHOLDS:
            if score >= threshold:
                return tier
        return "LOW"

    def _validate_weights(self) -> None:
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.01:
            raise ValueError(f"Risk weights must sum to 1.0 — got {total:.3f}")


def normalise_suricata_severity(severity: int) -> float:
    """
    Convert Suricata rule severity (1=high, 3=low) to 0.0–1.0 scale.
    Suricata convention: 1 = most severe, 3 = least severe.
    """
    mapping = {1: 1.0, 2: 0.65, 3: 0.30, 4: 0.10}
    return mapping.get(severity, 0.5)
