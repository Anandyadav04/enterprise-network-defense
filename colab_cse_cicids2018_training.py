# ==============================================================================
# CSE-CIC-IDS2018 Transformer Model Training & ONNX Export (Google Colab)
# Final Year Major Project: AI-Powered Enterprise Network Threat Detection
# ==============================================================================
# Covers Attack Scenarios mapped to SOC threat categories:
# - SQL Injection (Web attack)
# - XSS / Web Exploits (HTTP_EXPLOIT)
# - Brute Force (Web, FTP, SSH)
# - Botnet Communications (MALWARE)
# - Denial of Service (DoS GoldenEye, Slowloris, SlowHTTPTest, Hulk, DDoS)
# - Benign Enterprise Traffic
# ==============================================================================

import os
os.system("pip install --quiet huggingface_hub datasets scikit-learn onnx onnxruntime onnxscript pandas numpy torch")

import json
import logging
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from sklearn.utils.class_weight import compute_class_weight
from torch.utils.data import DataLoader, TensorDataset
from huggingface_hub import hf_hub_download
from google.colab import files

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# --- 1. CONFIGURATION ---
FEATURE_COLUMNS = [
    "duration", "packet_count", "byte_count",
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "iat_mean", "iat_std", "src_port", "dst_port",
    "dns_query_count", "payload_entropy", "behavior_anomaly_score",
]

# Standardized SOC Platform Classes (10 categories)
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
CLASS_TO_IDX = {cls: i for i, cls in enumerate(ATTACK_CLASSES)}

# Target files from HuggingFace repository (AhmedMahmoud165/CIC-IDS-2018)
# Notice: Files are located inside the 'data/' subfolder on Hugging Face!
TARGET_FILES = [
    "data/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",  # SQLi, XSS, Web Brute Force, Benign
    "data/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",    # Botnet (MALWARE), Benign
    "data/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv", # FTP/SSH Brute Force, Benign
    "data/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",  # DoS-GoldenEye, DoS-Slowloris, Benign
]

# Robust fuzzy label mapper to catch any naming variations
def map_label(raw_label: str) -> str:
    lbl = str(raw_label).strip().lower()
    if "benign" in lbl:
        return "BENIGN"
    elif "sql" in lbl:
        return "SQL_INJECTION"
    elif "xss" in lbl:
        return "HTTP_EXPLOIT"
    elif "bot" in lbl:
        return "MALWARE"
    elif "infilt" in lbl:
        return "DATA_EXFILTRATION"
    elif "ftp" in lbl or "ssh" in lbl or "brute" in lbl:
        return "BRUTE_FORCE"
    elif "dos" in lbl or "ddos" in lbl or "golden" in lbl or "slow" in lbl or "hulk" in lbl:
        return "DOS_DDOS"
    elif "scan" in lbl or "nmap" in lbl:
        return "PORT_SCAN"
    return None

# --- 2. MODEL DEFINITION ---
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

# --- 3. TRAINING PIPELINE ---
def run_colab_training():
    logger.info("==================================================================")
    logger.info("Step 1: Downloading & Preprocessing CSE-CIC-IDS2018 from Hugging Face...")
    logger.info("==================================================================")
    
    collected_dfs = []
    
    for filename in TARGET_FILES:
        try:
            logger.info(f"Downloading {filename} from Hugging Face...")
            local_path = hf_hub_download(
                repo_id="AhmedMahmoud165/CIC-IDS-2018",
                filename=filename,
                repo_type="dataset"
            )
            logger.info(f"Reading {filename}...")
            # Use encoding_errors='ignore' to prevent invalid byte crashes
            sub_df = pd.read_csv(local_path, low_memory=False, encoding_errors="ignore")
            
            # Normalize column names: lowercase, strip, replace whitespace and slashes
            sub_df.columns = [c.strip().lower().replace(" ", "_").replace("/", "_") for c in sub_df.columns]
            
            # Locate label column
            label_col = "label" if "label" in sub_df.columns else None
            if not label_col:
                for c in sub_df.columns:
                    if "label" in c:
                        label_col = c
                        break
            if not label_col:
                logger.warning(f"Could not find label column in {filename}, skipping.")
                continue
                
            # Filter out corrupt repeated header rows
            sub_df = sub_df[sub_df[label_col].astype(str).str.lower() != "label"]
            
            # Map attack strings to our standardized SOC categories
            sub_df["mapped_label"] = sub_df[label_col].apply(map_label)
            sub_df.dropna(subset=["mapped_label"], inplace=True)
            
            # Extract standard 14 network flow features
            # 1. Flow Duration
            dur_cols = [c for c in sub_df.columns if "duration" in c]
            sub_df["duration"] = pd.to_numeric(sub_df[dur_cols[0]], errors="coerce").fillna(0.0) if dur_cols else 0.0
            
            # 2. Packets
            fwd_p = [c for c in sub_df.columns if "tot_fwd_pkts" in c or "total_fwd_packets" in c or ("fwd" in c and "pkt" in c)]
            bwd_p = [c for c in sub_df.columns if "tot_bwd_pkts" in c or "total_backward_packets" in c or ("bwd" in c and "pkt" in c)]
            sub_df["fwd_packets"] = pd.to_numeric(sub_df[fwd_p[0]], errors="coerce").fillna(0.0) if fwd_p else 0.0
            sub_df["bwd_packets"] = pd.to_numeric(sub_df[bwd_p[0]], errors="coerce").fillna(0.0) if bwd_p else 0.0
            sub_df["packet_count"] = sub_df["fwd_packets"] + sub_df["bwd_packets"]
            
            # 3. Bytes
            fwd_b = [c for c in sub_df.columns if "totlen_fwd_pkts" in c or "total_length_of_fwd" in c or ("fwd" in c and "byt" in c) or ("fwd" in c and "len" in c)]
            bwd_b = [c for c in sub_df.columns if "totlen_bwd_pkts" in c or "total_length_of_bwd" in c or ("bwd" in c and "byt" in c) or ("bwd" in c and "len" in c)]
            sub_df["fwd_bytes"] = pd.to_numeric(sub_df[fwd_b[0]], errors="coerce").fillna(0.0) if fwd_b else 0.0
            sub_df["bwd_bytes"] = pd.to_numeric(sub_df[bwd_b[0]], errors="coerce").fillna(0.0) if bwd_b else 0.0
            sub_df["byte_count"] = sub_df["fwd_bytes"] + sub_df["bwd_bytes"]
            
            # 4. Inter-Arrival Time (IAT)
            iat_m = [c for c in sub_df.columns if "iat" in c and "mean" in c]
            iat_s = [c for c in sub_df.columns if "iat" in c and "std" in c]
            sub_df["iat_mean"] = pd.to_numeric(sub_df[iat_m[0]], errors="coerce").fillna(0.0) if iat_m else 0.0
            sub_df["iat_std"] = pd.to_numeric(sub_df[iat_s[0]], errors="coerce").fillna(0.0) if iat_s else 0.0
            
            # 5. Ports
            dst_p = [c for c in sub_df.columns if "dst_port" in c or "destination_port" in c or ("dst" in c and "port" in c)]
            src_p = [c for c in sub_df.columns if "src_port" in c or "source_port" in c or ("src" in c and "port" in c)]
            sub_df["dst_port"] = pd.to_numeric(sub_df[dst_p[0]], errors="coerce").fillna(0.0) if dst_p else 0.0
            sub_df["src_port"] = pd.to_numeric(sub_df[src_p[0]], errors="coerce").fillna(0.0) if src_p else 0.0
            
            # Placeholder telemetry
            sub_df["dns_query_count"] = 0.0
            sub_df["payload_entropy"] = 0.0
            sub_df["behavior_anomaly_score"] = 0.0
            
            # Balanced sampling per file:
            attack_samples = sub_df[sub_df["mapped_label"] != "BENIGN"]
            benign_samples = sub_df[sub_df["mapped_label"] == "BENIGN"]
            
            # Cap attack samples per file at 10,000 so Wednesday (380k brute force) doesn't flood RAM
            if len(attack_samples) > 10000:
                attack_samples = attack_samples.sample(n=10000, random_state=42)
                
            sample_benign_count = min(len(benign_samples), 10000)
            if sample_benign_count > 0:
                benign_samples = benign_samples.sample(n=sample_benign_count, random_state=42)
            
            balanced_sub = pd.concat([attack_samples, benign_samples])
            collected_dfs.append(balanced_sub[["mapped_label"] + FEATURE_COLUMNS])
            logger.info(f"Loaded {len(balanced_sub)} records from {filename} (Attacks: {len(attack_samples)}, Benign: {len(benign_samples)})")
            
        except Exception as e:
            logger.error(f"Error processing {filename}: {e}", exc_info=True)
            continue

    if not collected_dfs:
        raise ValueError("No data could be loaded! Please check Hugging Face connection.")
        
    df = pd.concat(collected_dfs, ignore_index=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # ── Intelligent Stratified Balancing & Minority Augmentation (SMOTE-style) ──
    logger.info("Applying balanced class resampling (capping majority, oversampling web attacks & botnets)...")
    TARGET_MAJORITY = 10000  # Cap massive classes (Brute Force, Benign, DoS) so they don't overpower minority attacks
    TARGET_MINORITY = 3000   # Oversample minority attacks (SQL Injection, XSS, Botnet) so they receive balanced attention
    
    balanced_chunks = []
    for label_name, group in df.groupby("mapped_label"):
        count = len(group)
        if count > TARGET_MAJORITY:
            sampled = group.sample(n=TARGET_MAJORITY, random_state=42)
        elif count < TARGET_MINORITY:
            oversampled = group.sample(n=TARGET_MINORITY, replace=True, random_state=42).copy()
            # Add subtle jitter (1e-4) to numerical features to provide synthetic variety
            jitter = np.random.normal(0, 1e-4, size=(TARGET_MINORITY, len(FEATURE_COLUMNS)))
            oversampled[FEATURE_COLUMNS] = oversampled[FEATURE_COLUMNS].values + jitter
            sampled = oversampled
        else:
            sampled = group
        balanced_chunks.append(sampled)

    df = pd.concat(balanced_chunks, ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    print("\n=======================================================")
    print("CSE-CIC-IDS2018 Balanced Training Distribution:")
    print("=======================================================")
    print(df["mapped_label"].value_counts())
    print("=======================================================\n")

    X = df[FEATURE_COLUMNS].values.astype(np.float32)
    y = df["mapped_label"].map(CLASS_TO_IDX).values.astype(np.int64)

    # Train / Test split (80% train, 20% test, stratified)
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )

    logger.info("Step 2: Normalizing Features with StandardScaler...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train).astype(np.float32)
    X_val = scaler.transform(X_val).astype(np.float32)

    # Save feature scaler configuration
    scaler_data = {"mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist()}
    with open("feature_scaler.json", "w") as f:
        json.dump(scaler_data, f)
    logger.info("Saved feature_scaler.json successfully.")

    # Convert to PyTorch DataLoaders
    train_loader = DataLoader(
        TensorDataset(torch.from_numpy(X_train), torch.from_numpy(y_train)),
        batch_size=128, shuffle=True
    )
    val_loader = DataLoader(
        TensorDataset(torch.from_numpy(X_val), torch.from_numpy(y_val)),
        batch_size=256, shuffle=False
    )

    # Compute inverse class weights
    present_classes = np.unique(y_train)
    weights = compute_class_weight(class_weight="balanced", classes=present_classes, y=y_train)
    full_weights = np.ones(len(ATTACK_CLASSES), dtype=np.float32)
    for cls_idx, w in zip(present_classes, weights):
        full_weights[cls_idx] = w

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Step 3: Training Transformer Encoder on device: {device}...")
    
    model = NetworkTransformerClassifier(
        input_dim=len(FEATURE_COLUMNS),
        num_classes=len(ATTACK_CLASSES),
        d_model=64,
        nhead=4,
        num_layers=3,
        dropout=0.1
    ).to(device)

    criterion = nn.CrossEntropyLoss(weight=torch.tensor(full_weights, dtype=torch.float32).to(device))
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001, weight_decay=1e-4)

    # Train for 6 epochs
    model.train()
    for epoch in range(6):
        total_loss, correct, total = 0.0, 0, 0
        for X_b, y_b in train_loader:
            X_b, y_b = X_b.to(device), y_b.to(device)
            optimizer.zero_grad()
            out = model(X_b)
            loss = criterion(out, y_b)
            loss.backward()
            optimizer.step()

            total_loss += loss.item() * len(y_b)
            correct += (out.argmax(dim=1) == y_b).sum().item()
            total += len(y_b)

        logger.info(f"Epoch {epoch+1}/6 - Loss: {total_loss/total:.4f} | Training Accuracy: {correct/total*100:.2f}%")

    logger.info("Step 4: Evaluating on Held-Out Test Set...")
    model.eval()
    all_preds, all_labels = [], []
    with torch.no_grad():
        for X_b, y_b in val_loader:
            preds = model(X_b.to(device)).argmax(dim=1).cpu().numpy()
            all_preds.extend(preds)
            all_labels.extend(y_b.numpy())

    unique_labels = sorted(list(set(all_labels) | set(all_preds)))
    target_names_present = [ATTACK_CLASSES[i] for i in unique_labels]

    report = classification_report(
        all_labels, all_preds, labels=unique_labels, target_names=target_names_present, digits=4
    )
    print("\n=======================================================")
    print("CSE-CIC-IDS2018 Balanced Test Set Classification Report:")
    print("=======================================================")
    print(report)
    print("=======================================================\n")

    # Step 5: Export to ONNX (opset_version=18)
    logger.info("Step 5: Exporting Transformer Model to ONNX format...")
    dummy_input = torch.zeros(1, len(FEATURE_COLUMNS))
    torch.onnx.export(
        model.cpu(),
        dummy_input,
        "network_classifier.onnx",
        input_names=["features"],
        output_names=["probabilities"],
        dynamic_axes={"features": {0: "batch_size"}},
        opset_version=18,
    )
    logger.info("✅ Successfully exported to network_classifier.onnx!")
    
    # Download exported model and scaler
    try:
        files.download("network_classifier.onnx")
        files.download("feature_scaler.json")
    except Exception:
        logger.info("Colab auto-download completed. Files are saved in session storage.")

if __name__ == "__main__":
    run_colab_training()
