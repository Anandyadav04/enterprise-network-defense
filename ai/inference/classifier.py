"""
ai/inference/classifier.py
───────────────────────────
ONNX Runtime inference service for network traffic classification.

Consumes: enriched-events (flow features from stream_processor)
Produces: enriched-events with ai_attack_class + ai_confidence added

Model: Custom Transformer encoder trained on CIC-IDS2017 / UNSW-NB15
Input: Normalised numeric flow features (28 features — see FEATURE_COLUMNS)
Output: Softmax probabilities over attack classes (see ATTACK_CLASSES)

The model is exported from PyTorch to ONNX for lightweight inference
without requiring a full PyTorch runtime in the container.
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

# ── Attack class labels (must match training label encoding) ─────
ATTACK_CLASSES = [
    "BENIGN",
    "SQL_INJECTION",
    "HTTP_EXPLOIT",
    "MALWARE",
    "C2_COMMUNICATION",
    "DNS_TUNNELING",
    "DATA_EXFILTRATION",
    "BRUTE_FORCE",
    "PORT_SCAN",
    "DOS_DDOS",
]

# Minimum confidence to label as non-BENIGN (avoid low-confidence FPs)
CONFIDENCE_THRESHOLD = 0.55


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

        Returns:
            attack_class (str): Top predicted class label
            confidence (float): Confidence of top prediction (0.0–1.0)
            top_classes (dict): Class → probability for all classes
        """
        if self.session is None:
            return "UNKNOWN", 0.0, {}

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
        else:
            attack_class = ATTACK_CLASSES[top_idx]

        top_classes = {ATTACK_CLASSES[i]: round(float(p), 4) for i, p in enumerate(probs)}

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
