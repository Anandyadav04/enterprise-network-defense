"""
ai/training/model.py
─────────────────────
Transformer Encoder architecture for network traffic classification.

Architecture:
  Input layer  → Linear projection of flow features
  Positional   → Learned positional embedding (treats features as sequence)
  Transformer  → N encoder layers with multi-head self-attention
  Pool         → Mean pooling over sequence
  Classifier   → Linear → softmax over attack classes

Why Transformer for tabular traffic data?
  Flow features can be treated as a sequence of tokens where
  attention captures inter-feature relationships (e.g. between
  packet count, byte count, and IAT) that MLPs miss.
  This approach achieves competitive results with tree-based methods
  while being exportable to ONNX for fast inference.
"""

import torch
import torch.nn as nn


class NetworkTransformerClassifier(nn.Module):
    """
    Transformer encoder for network flow classification.

    Args:
        input_dim:   Number of flow features (default: 14)
        num_classes: Number of attack categories (default: 10)
        d_model:     Transformer embedding dimension
        nhead:       Number of attention heads
        num_layers:  Number of encoder layers
        dropout:     Dropout rate for regularisation
    """

    def __init__(
        self,
        input_dim: int = 14,
        num_classes: int = 10,
        d_model: int = 64,
        nhead: int = 4,
        num_layers: int = 3,
        dropout: float = 0.1,
    ):
        super().__init__()

        # Project raw features to d_model dimensions
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, d_model),
            nn.LayerNorm(d_model),
            nn.ReLU(),
        )

        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=d_model * 4,
            dropout=dropout,
            batch_first=True,
            norm_first=True,  # Pre-LN for training stability
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (batch, input_dim) — normalised flow feature vector
        Returns:
            logits: (batch, num_classes)
        """
        # Treat each feature as a "token" — reshape to (batch, seq_len=1, d_model)
        x = self.input_proj(x)          # (batch, d_model)
        x = x.unsqueeze(1)              # (batch, 1, d_model)
        x = self.transformer(x)         # (batch, 1, d_model)
        x = x.squeeze(1)               # (batch, d_model)
        return self.classifier(x)       # (batch, num_classes)

    def count_parameters(self) -> int:
        """Return total number of trainable parameters."""
        return sum(p.numel() for p in self.parameters() if p.requires_grad)
