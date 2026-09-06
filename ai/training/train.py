"""
ai/training/train.py
─────────────────────
Training script for the Transformer-based network traffic classifier.

Dataset: CIC-IDS2017 or UNSW-NB15 (place CSV files in ai/dataset/)
Model:   Custom Transformer Encoder (positional + attention over flow features)
Output:  Saved as PyTorch .pt checkpoint + ONNX export for production inference

Usage:
  python -m ai.training.train --dataset cicids2017 --epochs 30

Evaluation:
  Reports per-class Precision, Recall, F1 on held-out test set.
  Saves results to docs/evaluation_results.md
"""

import argparse
import json
import logging
import os
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset

from ai.preprocessing.feature_extractor import load_dataset, FEATURE_COLUMNS, LABEL_COLUMN
from ai.training.model import NetworkTransformerClassifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).parent.parent / "models"
MODELS_DIR.mkdir(exist_ok=True)


def train(dataset_name: str, epochs: int, batch_size: int, lr: float) -> None:
    """Full training pipeline: load → preprocess → train → evaluate → export."""

    # ── Load dataset ─────────────────────────────────────────────
    logger.info("Loading dataset: %s", dataset_name)
    X, y, class_names = load_dataset(dataset_name)
    logger.info("Dataset shape: X=%s, classes=%s", X.shape, class_names)

    # ── Train/val/test split (70/15/15) ──────────────────────────
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, stratify=y, random_state=42)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42)

    # ── Feature normalisation ─────────────────────────────────────
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train).astype(np.float32)
    X_val   = scaler.transform(X_val).astype(np.float32)
    X_test  = scaler.transform(X_test).astype(np.float32)

    # Save scaler for inference
    scaler_data = {"mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist()}
    with open(MODELS_DIR / "feature_scaler.json", "w") as f:
        json.dump(scaler_data, f)
    logger.info("Scaler saved to %s", MODELS_DIR / "feature_scaler.json")

    # ── Build DataLoaders ─────────────────────────────────────────
    def to_loader(X_arr, y_arr, shuffle=False):
        ds = TensorDataset(torch.tensor(X_arr), torch.tensor(y_arr, dtype=torch.long))
        return DataLoader(ds, batch_size=batch_size, shuffle=shuffle)

    train_loader = to_loader(X_train, y_train, shuffle=True)
    val_loader   = to_loader(X_val, y_val)
    test_loader  = to_loader(X_test, y_test)

    # ── Model ─────────────────────────────────────────────────────
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info("Training on device: %s", device)

    model = NetworkTransformerClassifier(
        input_dim=len(FEATURE_COLUMNS),
        num_classes=len(class_names),
    ).to(device)

    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
    criterion = nn.CrossEntropyLoss()

    # ── Training loop ─────────────────────────────────────────────
    best_val_acc = 0.0
    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            optimizer.zero_grad()
            logits = model(X_batch)
            loss = criterion(logits, y_batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        val_acc = evaluate(model, val_loader, device)
        scheduler.step()
        logger.info("Epoch %d/%d | Loss=%.4f | Val Acc=%.2f%%", epoch, epochs, total_loss, val_acc * 100)

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            torch.save(model.state_dict(), MODELS_DIR / "network_classifier.pt")
            logger.info("Checkpoint saved (val_acc=%.2f%%)", val_acc * 100)

    # ── Final test evaluation ─────────────────────────────────────
    model.load_state_dict(torch.load(MODELS_DIR / "network_classifier.pt"))
    model.eval()
    all_preds, all_labels = [], []
    with torch.no_grad():
        for X_batch, y_batch in test_loader:
            preds = model(X_batch.to(device)).argmax(dim=1).cpu().numpy()
            all_preds.extend(preds)
            all_labels.extend(y_batch.numpy())

    report = classification_report(all_labels, all_preds, target_names=class_names)
    logger.info("\nTest Set Classification Report:\n%s", report)

    docs_dir = Path(__file__).parent.parent.parent / "docs"
    docs_dir.mkdir(exist_ok=True)
    with open(docs_dir / "evaluation_results.md", "w") as f:
        f.write(f"# Model Evaluation Results\n\n## Dataset: {dataset_name}\n\n```\n{report}\n```\n")

    # ── ONNX Export ───────────────────────────────────────────────
    dummy_input = torch.zeros(1, len(FEATURE_COLUMNS))
    torch.onnx.export(
        model.cpu(),
        dummy_input,
        str(MODELS_DIR / "network_classifier.onnx"),
        input_names=["features"],
        output_names=["probabilities"],
        dynamic_axes={"features": {0: "batch_size"}},
        opset_version=14,
    )
    logger.info("ONNX model exported to %s", MODELS_DIR / "network_classifier.onnx")


def evaluate(model, loader, device) -> float:
    """Compute accuracy on a DataLoader."""
    model.eval()
    correct, total = 0, 0
    with torch.no_grad():
        for X_batch, y_batch in loader:
            preds = model(X_batch.to(device)).argmax(dim=1)
            correct += (preds.cpu() == y_batch).sum().item()
            total += len(y_batch)
    return correct / total if total > 0 else 0.0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train network traffic classifier")
    parser.add_argument("--dataset", default="cicids2017", choices=["cicids2017", "unswnb15"])
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--lr", type=float, default=1e-3)
    args = parser.parse_args()
    train(args.dataset, args.epochs, args.batch_size, args.lr)
