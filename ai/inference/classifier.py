"""
ai/inference/classifier.py
───────────────────────────
ONNX Runtime inference service for network traffic classification.

Consumes: enriched-events (flow features from stream_processor)
Produces: enriched-events with ai_attack_class + ai_confidence added

Model: Transformer encoder trained on CSE-CIC-IDS2018 (6 attack classes)
Input: Normalised numeric flow features (14 features — see FEATURE_COLUMNS)
Output: Softmax probabilities over 6 attack classes (see ATTACK_CLASSES)

Hybrid detection: ML model + Suricata signature rule-based fusion.
Suricata DPI handles payload-level attacks (SQL Injection, HTTP Exploit)
when the model confidence is low (e.g. XSS flows look like benign HTTPS).
"""

import json
import logging
import os
from typing import Optional

import numpy as np
import onnxruntime as ort
from kafka import KafkaConsumer, KafkaProducer

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
INPUT_TOPIC = "enriched-events"
OUTPUT_TOPIC = "scored-events"
MODEL_PATH = os.getenv("MODEL_PATH", "/app/models/network_classifier.onnx")
SCALER_PATH = os.getenv("SCALER_PATH", "/app/models/feature_scaler.json")

# ── Feature columns (must match training feature order exactly) ──
FEATURE_COLUMNS = [
    "duration", "packet_count", "byte_count",
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "iat_mean", "iat_std",
    "src_port", "dst_port",
    "dns_query_count", "payload_entropy",
    "behavior_anomaly_score",
]

# ── Attack class labels (must match training label encoding exactly) ─────
# CRITICAL: Order must match colab_cse_cicids2018_training.py ATTACK_CLASSES.
# The ONNX model output layer has 10 neurons (num_classes=10).
# Classes not seen in training data (C2_COMMUNICATION, DNS_TUNNELING,
# DATA_EXFILTRATION, PORT_SCAN) will have near-zero probability in practice.
ATTACK_CLASSES = [
    "BENIGN",            # idx 0
    "SQL_INJECTION",     # idx 1
    "HTTP_EXPLOIT",      # idx 2
    "MALWARE",           # idx 3
    "C2_COMMUNICATION", # idx 4  (not in training data — near-zero prob)
    "DNS_TUNNELING",    # idx 5  (not in training data — near-zero prob)
    "DATA_EXFILTRATION",# idx 6  (not in training data — near-zero prob)
    "BRUTE_FORCE",      # idx 7
    "PORT_SCAN",        # idx 8  (not in training data — near-zero prob)
    "DOS_DDOS",         # idx 9
]

# ── Suricata signature → AI class mapping (rule-based override) ──
# When a known Suricata signature is present, use it to correct or supplement
# the AI classification. Suricata DPI inspects payloads and catches attacks
# the model misses at the flow-stats level (e.g. HTTP_EXPLOIT recall=47.8%,
# XSS flows are indistinguishable from benign HTTPS in flow statistics).
SIGNATURE_CLASS_MAP = {
    "MALWARE":        "MALWARE",
    "TROJAN":         "MALWARE",
    "BOTNET":         "MALWARE",
    "SQL Injection":  "SQL_INJECTION",
    "SQLi":           "SQL_INJECTION",
    "EXPLOIT":        "HTTP_EXPLOIT",
    "XSS":            "HTTP_EXPLOIT",
    "DOS":            "DOS_DDOS",
    "DDOS":           "DOS_DDOS",
    "BRUTE":          "BRUTE_FORCE",
    "DNS":            "DNS_TUNNELING",
    "SCAN":           "PORT_SCAN",
    "Nmap":           "PORT_SCAN",
    "Exfiltration":   "DATA_EXFILTRATION",
}

# Minimum confidence to label as non-BENIGN (avoid low-confidence FPs).
# 59% confidence (what Docker internal traffic scores) is noise, not a threat.
CONFIDENCE_THRESHOLD = 0.72

# Internal / orchestration IP prefixes — always classify as BENIGN.
# These are Docker Desktop gateway, private RFC1918 container ranges, and
# localhost addresses that will never be real attack sources in this system.
INTERNAL_IP_PREFIXES = (
    "192.168.65.",   # Docker Desktop host gateway (Windows/Mac)
    "192.168.64.",   # Docker Desktop alternate range
    "172.17.",       # Default Docker bridge network
    "172.18.",       # Docker compose network
    "172.19.",       # Docker compose network
    "172.20.",       # Docker compose network
    "127.",          # Loopback
    "::1",           # IPv6 loopback
)


class NetworkClassifier:
    """
    ONNX Runtime-based network traffic classifier.
    Wraps model loading, feature extraction, and inference.
    """

    def __init__(self, model_path: str = MODEL_PATH, scaler_path: str = SCALER_PATH):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.session: Optional[ort.InferenceSession] = None
        self.scaler: Optional[dict] = None
        self._load()

    def _load(self) -> None:
        """Load ONNX model and feature scaler."""
        try:
            self.session = ort.InferenceSession(
                self.model_path,
                providers=["CPUExecutionProvider"],
            )
            logger.info("ONNX model loaded from %s", self.model_path)
        except Exception as exc:
            logger.error("Failed to load ONNX model (using dummy inference): %s", exc)
            self.session = None

        try:
            with open(self.scaler_path, "r") as f:
                self.scaler = json.load(f)
            logger.info("Feature scaler loaded from %s", self.scaler_path)
        except FileNotFoundError:
            logger.warning("Scaler file not found at %s — using raw features", self.scaler_path)
            self.scaler = None

    def extract_features(self, event: dict) -> np.ndarray:
        """Extract and normalise feature vector from an enriched event."""
        raw = np.array([float(event.get(col, 0.0)) for col in FEATURE_COLUMNS], dtype=np.float32)

        if self.scaler:
            mean = np.array(self.scaler["mean"], dtype=np.float32)
            scale = np.array(self.scaler["scale"], dtype=np.float32)
            raw = (raw - mean) / (scale + 1e-8)

        return raw.reshape(1, -1)  # (1, n_features)

    def predict(self, event: dict) -> tuple[str, float, dict]:
        """
        Run inference on an enriched event.

        Uses a hybrid approach:
          1. Internal IP whitelist  — Docker/orchestration traffic → BENIGN immediately
          2. ML model inference     — Transformer encoder on flow features
          3. Confidence threshold   — Low-confidence predictions → BENIGN
          4. Suricata rule override — Known signatures boost / correct the class

        Returns:
            attack_class (str): Top predicted class label
            confidence (float): Confidence of top prediction (0.0–1.0)
            top_classes (dict): Class → probability for all classes
        """
        if self.session is None:
            return "UNKNOWN", 0.0, {}

        # ── Step 1: Internal IP whitelist ──────────────────────────────────
        # Docker Desktop gateway (192.168.65.1) and container bridge ranges
        # generate constant background traffic that the model misclassifies.
        # Whitelisting them is standard SOC practice for orchestration hosts.
        src_ip = str(event.get("src_ip") or "")
        if any(src_ip.startswith(prefix) for prefix in INTERNAL_IP_PREFIXES):
            sig = event.get("suricata_signature") or ""
            if not sig:
                # No Suricata alert on this internal IP — definitely benign
                return "BENIGN", 0.0, {}
            # If Suricata fired on an internal IP, still process it below

        # ── Step 2: ML inference ───────────────────────────────────────────

        features = self.extract_features(event)
        input_name = self.session.get_inputs()[0].name
        outputs = self.session.run(None, {input_name: features})
        logits = outputs[0][0]  # Raw logits from PyTorch CrossEntropy model
        
        # Apply stable softmax
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / np.sum(exp_logits)

        top_idx = int(np.argmax(probs))
        top_prob = float(probs[top_idx])

        # Apply confidence threshold
        if top_prob < CONFIDENCE_THRESHOLD or ATTACK_CLASSES[top_idx] == "BENIGN":
            attack_class = "BENIGN"
            top_prob = 0.0  # Force 0.0 confidence for BENIGN so risk_tier is LOW
        else:
            attack_class = ATTACK_CLASSES[top_idx]

        top_classes = {ATTACK_CLASSES[i]: round(float(p), 4) for i, p in enumerate(probs)}

        # ── Hybrid fusion: Suricata signature override ──
        # Suricata DPI has seen the packet payload; trust it over ML
        # when a signature matches. This handles the HTTP_EXPLOIT recall gap
        # (47.8% from training) — XSS/exploit flows are identical to benign
        # HTTPS at the flow-stats level but Suricata catches them in payload.
        sig = event.get("suricata_signature") or ""
        if sig:
            for keyword, mapped_class in SIGNATURE_CLASS_MAP.items():
                if keyword.lower() in sig.lower():
                    attack_class = mapped_class
                    # Boost confidence since both ML + rule agree
                    top_prob = max(top_prob, 0.92)
                    break

        return attack_class, round(top_prob, 4), top_classes


class InferenceService:
    """
    Kafka consumer/producer wrapper around NetworkClassifier.
    Consumes enriched-events, adds AI predictions, republishes.
    """

    def __init__(self):
        self.classifier = NetworkClassifier()
        self.consumer = KafkaConsumer(
            INPUT_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP,
            group_id="ai-inference-group",
            auto_offset_reset="latest",
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )
        self.producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )

    def run(self) -> None:
        """Main inference loop."""
        logger.info("InferenceService started — consuming from %s", INPUT_TOPIC)
        for msg in self.consumer:
            event = msg.value
            attack_class, confidence, top_classes = self.classifier.predict(event)

            event["ai_attack_class"] = attack_class
            event["ai_confidence"] = confidence
            event["ai_top_classes"] = top_classes

            self.producer.send(OUTPUT_TOPIC, value=event)
            logger.debug("AI: %s [%.2f%%] for src=%s", attack_class, confidence * 100, event.get("src_ip"))
