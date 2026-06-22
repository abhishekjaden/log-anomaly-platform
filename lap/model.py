#!/usr/bin/env python3
"""
lap.model — the anomaly-detection autoencoder, shared by training and inference.

Deliberately small (per the blueprint, the infrastructure is the star, not the
model): a dense undercomplete autoencoder. It learns to reconstruct NORMAL request
feature vectors; at inference, reconstruction error is the anomaly score -- high
error means the request resembles nothing it learned as normal.

torch is imported only here, so services that just parse/featurize never load it.
"""
from __future__ import annotations

import torch
import torch.nn as nn


class AutoEncoder(nn.Module):
    def __init__(self, n_features: int, hidden: int = 12, latent: int = 6):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(n_features, hidden), nn.ReLU(),
            nn.Linear(hidden, latent), nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent, hidden), nn.ReLU(),
            nn.Linear(hidden, n_features),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


def reconstruction_error(model: "AutoEncoder", x: torch.Tensor) -> torch.Tensor:
    """Per-row mean squared error between each input and its reconstruction."""
    with torch.no_grad():
        recon = model(x)
        return ((recon - x) ** 2).mean(dim=1)