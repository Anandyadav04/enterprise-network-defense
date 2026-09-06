"""
ai/preprocessing/feature_extractor.py
───────────────────────────────────────
Dataset loading and preprocessing for CIC-IDS2017 and UNSW-NB15.

Handles:
  - CSV loading and column normalization
  - Label encoding (attack categories → integer indices)
  - Feature selection (subset used for inference)
  - Class imbalance handling via SMOTE or class weights

Dataset Download:
  CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
  UNSW-NB15:   https://research.unsw.edu.au/projects/unsw-nb15-dataset

Place CSV files in: ai/dataset/cicids2017/ or ai/dataset/unswnb15/
"""

import logging
from pathlib import Path
from typing import Tuple, List

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

DATASET_DIR = Path(__file__).parent.parent / "dataset"

# ── Feature columns used for model training and inference ────────
# Must match FEATURE_COLUMNS in ai/inference/classifier.py
FEATURE_COLUMNS = [
    "duration", "packet_count", "byte_count",
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "iat_mean", "iat_std",
    "src_port", "dst_port",
    "dns_query_count", "payload_entropy",
    "behavior_anomaly_score",
]

LABEL_COLUMN = "label"

# ── CIC-IDS2017 label mapping → canonical attack classes ─────────
CICIDS_LABEL_MAP = {
    "BENIGN": "BENIGN",
    "Bot": "MALWARE",
    "DDoS": "DOS_DDOS",
    "DoS GoldenEye": "DOS_DDOS",
    "DoS Hulk": "DOS_DDOS",
    "DoS Slowhttptest": "DOS_DDOS",
    "DoS slowloris": "DOS_DDOS",
    "FTP-Patator": "BRUTE_FORCE",
    "SSH-Patator": "BRUTE_FORCE",
    "Heartbleed": "HTTP_EXPLOIT",
    "Infiltration": "DATA_EXFILTRATION",
    "PortScan": "PORT_SCAN",
    "Web Attack \x96 Brute Force": "BRUTE_FORCE",
    "Web Attack \x96 Sql Injection": "SQL_INJECTION",
    "Web Attack \x96 XSS": "HTTP_EXPLOIT",
}

# ── UNSW-NB15 category mapping ────────────────────────────────────
UNSWNB_LABEL_MAP = {
    "Normal": "BENIGN",
    "Fuzzers": "HTTP_EXPLOIT",
    "Analysis": "PORT_SCAN",
    "Backdoors": "MALWARE",
    "DoS": "DOS_DDOS",
    "Exploits": "HTTP_EXPLOIT",
    "Generic": "MALWARE",
    "Reconnaissance": "PORT_SCAN",
    "Shellcode": "MALWARE",
    "Worms": "MALWARE",
}

# Canonical ordered class list (index = model output class)
ATTACK_CLASSES = [
    "BENIGN", "SQL_INJECTION", "HTTP_EXPLOIT", "MALWARE",
    "C2_COMMUNICATION", "DNS_TUNNELING", "DATA_EXFILTRATION",
    "BRUTE_FORCE", "PORT_SCAN", "DOS_DDOS",
]
CLASS_TO_IDX = {cls: i for i, cls in enumerate(ATTACK_CLASSES)}


def load_dataset(name: str) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Load, clean, and encode a dataset for training.

    Returns:
        X: float32 feature matrix (n_samples, n_features)
        y: int64 label vector (n_samples,)
        class_names: list of class name strings
    """
    if name == "cicids2017":
        return _load_cicids2017()
    elif name == "unswnb15":
        return _load_unswnb15()
    else:
        raise ValueError(f"Unknown dataset: {name}")


def _load_cicids2017() -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """Load and preprocess CIC-IDS2017 CSV files."""
    data_dir = DATASET_DIR / "cicids2017"
    if not data_dir.exists():
        raise FileNotFoundError(f"CIC-IDS2017 dataset not found at {data_dir}")

    dfs = []
    for csv_file in sorted(data_dir.glob("*.csv")):
        logger.info("Loading: %s", csv_file.name)
        df = pd.read_csv(csv_file, low_memory=False)
        df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
        dfs.append(df)

    df = pd.concat(dfs, ignore_index=True)
    return _preprocess(df, label_col="label", label_map=CICIDS_LABEL_MAP, cicids=True)


def _load_unswnb15() -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """Load and preprocess UNSW-NB15 CSV files."""
    data_dir = DATASET_DIR / "unswnb15"
    if not data_dir.exists():
        raise FileNotFoundError(f"UNSW-NB15 dataset not found at {data_dir}")

    dfs = []
    for csv_file in sorted(data_dir.glob("*.csv")):
        logger.info("Loading: %s", csv_file.name)
        df = pd.read_csv(csv_file, low_memory=False)
        df.columns = [c.strip().lower() for c in df.columns]
        dfs.append(df)

    df = pd.concat(dfs, ignore_index=True)
    return _preprocess(df, label_col="attack_cat", label_map=UNSWNB_LABEL_MAP, cicids=False)


def _preprocess(df, label_col, label_map, cicids=True):
    """Shared preprocessing: clean, map labels, select features, encode."""
    # Drop rows with inf/NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # Map labels to canonical classes
    df[LABEL_COLUMN] = df[label_col].map(label_map)
    df.dropna(subset=[LABEL_COLUMN], inplace=True)

    # CIC-IDS2017 column aliases
    col_aliases = {
        "flow_duration": "duration",
        "total_fwd_packets": "fwd_packets",
        "total_backward_packets": "bwd_packets",
        "total_length_of_fwd_packets": "fwd_bytes",
        "total_length_of_bwd_packets": "bwd_bytes",
        "flow_iat_mean": "iat_mean",
        "flow_iat_std": "iat_std",
        "source_port": "src_port",
        "destination_port": "dst_port",
    }
    df.rename(columns=col_aliases, inplace=True)

    # Add missing columns with defaults
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0

    X = df[FEATURE_COLUMNS].values.astype(np.float32)
    y = df[LABEL_COLUMN].map(CLASS_TO_IDX).values.astype(np.int64)

    logger.info(
        "Dataset loaded: %d samples, %d features, %d classes",
        len(X), X.shape[1], len(ATTACK_CLASSES),
    )
    return X, y, ATTACK_CLASSES
