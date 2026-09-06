# Run this in a Google Colab Cell

# 1. Install required packages
import os
os.system("pip install datasets scikit-learn onnx onnxruntime onnxscript pandas numpy torch")

import json
import logging
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset
from datasets import load_dataset
from google.colab import files

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
FEATURE_COLUMNS = [
    "duration", "packet_count", "byte_count",
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "iat_mean", "iat_std", "src_port", "dst_port",
    "dns_query_count", "payload_entropy", "behavior_anomaly_score",
]

CICIDS_LABEL_MAP = {
    "BENIGN": "BENIGN", "Bot": "MALWARE", "DDoS": "DOS_DDOS",
    "DoS GoldenEye": "DOS_DDOS", "DoS Hulk": "DOS_DDOS",
    "DoS Slowhttptest": "DOS_DDOS", "DoS slowloris": "DOS_DDOS",
    "FTP-Patator": "BRUTE_FORCE", "SSH-Patator": "BRUTE_FORCE",
    "Heartbleed": "HTTP_EXPLOIT", "Infiltration": "DATA_EXFILTRATION",
    "PortScan": "PORT_SCAN", "Web Attack \x96 Brute Force": "BRUTE_FORCE",
    "Web Attack \x96 Sql Injection": "SQL_INJECTION", "Web Attack \x96 XSS": "HTTP_EXPLOIT",
}

ATTACK_CLASSES = [
    "BENIGN", "SQL_INJECTION", "HTTP_EXPLOIT", "MALWARE",
    "C2_COMMUNICATION", "DNS_TUNNELING", "DATA_EXFILTRATION",
    "BRUTE_FORCE", "PORT_SCAN", "DOS_DDOS",
]
CLASS_TO_IDX = {cls: i for i, cls in enumerate(ATTACK_CLASSES)}

# --- MODEL DEFINITION ---
class NetworkTransformerClassifier(nn.Module):
    def __init__(self, input_dim=14, num_classes=10, d_model=64, nhead=4, num_layers=3, dropout=0.1):
        super().__init__()
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, d_model),
            nn.LayerNorm(d_model),
            nn.ReLU(),
        )
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=d_model * 4,
            dropout=dropout, batch_first=True, norm_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.classifier = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.input_proj(x)
        x = x.unsqueeze(1)
        x = self.transformer(x)
        x = x.squeeze(1)
        return self.classifier(x)

# --- TRAINING PIPELINE ---
def run_colab_training():
    logger.info("1. Downloading FULL CIC-IDS2017 Dataset from Hugging Face...")
    dataset = load_dataset("rdpahalavan/CIC-IDS2017", data_files="Network-Flows/*.parquet", split="train")
    df = dataset.to_pandas()
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    logger.info("2. Preprocessing Data...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    df["label"] = df["attack_label"].map(CICIDS_LABEL_MAP)
    df.dropna(subset=["label"], inplace=True)
    
    col_aliases = {
        "flow_duration": "duration", "total_fwd_packets": "fwd_packets",
        "total_backward_packets": "bwd_packets", "total_length_of_fwd_packets": "fwd_bytes",
        "total_length_of_bwd_packets": "bwd_bytes", "flow_iat_mean": "iat_mean",
        "flow_iat_std": "iat_std", "source_port": "src_port", "destination_port": "dst_port",
    }
    df.rename(columns=col_aliases, inplace=True)
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0

    X = df[FEATURE_COLUMNS].values.astype(np.float32)
    y = df["label"].map(CLASS_TO_IDX).values.astype(np.int64)

    # Train/Val Split
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    logger.info("3. Scaling Features...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train).astype(np.float32)
    X_val = scaler.transform(X_val).astype(np.float32)

    scaler_data = {"mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist()}
    with open("feature_scaler.json", "w") as f:
        json.dump(scaler_data, f)

    train_loader = DataLoader(TensorDataset(torch.tensor(X_train), torch.tensor(y_train)), batch_size=1024, shuffle=True)
    val_loader = DataLoader(TensorDataset(torch.tensor(X_val), torch.tensor(y_val)), batch_size=1024)

    logger.info("4. Initializing Transformer...")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = NetworkTransformerClassifier(input_dim=len(FEATURE_COLUMNS), num_classes=len(ATTACK_CLASSES)).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3)
    criterion = nn.CrossEntropyLoss()

    epochs = 15
    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0
        for X_b, y_b in train_loader:
            X_b, y_b = X_b.to(device), y_b.to(device)
            optimizer.zero_grad()
            loss = criterion(model(X_b), y_b)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        # Quick val acc
        model.eval()
        correct, total = 0, 0
        with torch.no_grad():
            for X_b, y_b in val_loader:
                preds = model(X_b.to(device)).argmax(dim=1)
                correct += (preds.cpu() == y_b).sum().item()
                total += len(y_b)
        logger.info(f"Epoch {epoch}/{epochs} | Loss={total_loss:.4f} | Val Acc={correct/total*100:.2f}%")

    logger.info("5. Exporting to ONNX...")
    # Safety save: Download the PyTorch weights in case ONNX export fails again!
    torch.save(model.state_dict(), "network_classifier_backup.pt")
    files.download("network_classifier_backup.pt")
    
    dummy_input = torch.zeros(1, len(FEATURE_COLUMNS)).to(device)
    torch.onnx.export(
        model, dummy_input, "network_classifier.onnx",
        input_names=["features"], output_names=["probabilities"],
        dynamic_axes={"features": {0: "batch_size"}}, opset_version=14,
    )

    logger.info("6. Triggering Download...")
    files.download("network_classifier.onnx")
    files.download("feature_scaler.json")
    logger.info("DONE!")

if __name__ == "__main__":
    run_colab_training()
