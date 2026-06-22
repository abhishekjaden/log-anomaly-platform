#!/usr/bin/env python3
"""
Train the anomaly-detection autoencoder on a normal-only corpus.

  parse -> featurize -> standardize (fit mean/std on normal) -> train AE ->
  set threshold from the normal reconstruction-error distribution -> save bundle.

The saved bundle (ml/models/detector.pt) carries everything inference needs:
weights, scaler stats, threshold, and feature order -- so serving scores identically.
"""
from __future__ import annotations

import argparse
import os

import numpy as np
import torch

from lap.parser import parse_file
from lap.features import featurize, FEATURE_NAMES, N_FEATURES
from lap.model import AutoEncoder, reconstruction_error


def load_matrix(path: str) -> np.ndarray:
    rows = [featurize(rec) for rec in parse_file(path)]
    if not rows:
        raise SystemExit(f"no parseable lines in {path}")
    return np.asarray(rows, dtype=np.float32)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--normal", default="data/sample/access_normal.log")
    ap.add_argument("--out", default="ml/models/detector.pt")
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--batch", type=int, default=128)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--pct", type=float, default=99.0, help="threshold percentile of normal errors")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    X = load_matrix(args.normal)
    print(f"loaded {len(X)} normal samples, {X.shape[1]} features")

    # standardize on the normal corpus; keep stats for inference
    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std == 0.0] = 1.0
    Xt = torch.from_numpy((X - mean) / std)

    model = AutoEncoder(N_FEATURES)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr)
    loss_fn = torch.nn.MSELoss()

    n = len(Xt)
    for epoch in range(1, args.epochs + 1):
        model.train()
        perm = torch.randperm(n)
        total = 0.0
        for i in range(0, n, args.batch):
            idx = perm[i:i + args.batch]
            batch = Xt[idx]
            opt.zero_grad()
            loss = loss_fn(model(batch), batch)
            loss.backward()
            opt.step()
            total += loss.item() * len(idx)
        if epoch == 1 or epoch % 10 == 0:
            print(f"epoch {epoch:3d}  train_mse {total / n:.6f}")

    model.eval()
    errs = reconstruction_error(model, Xt).numpy()
    threshold = float(np.percentile(errs, args.pct))
    print(f"normal error: mean {errs.mean():.5f}  p{args.pct:g}={threshold:.5f}  max {errs.max():.5f}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    torch.save({
        "state_dict": model.state_dict(),
        "mean": mean, "std": std,
        "threshold": threshold,
        "feature_names": FEATURE_NAMES,
        "n_features": N_FEATURES,
        "arch": {"hidden": 12, "latent": 6},
    }, args.out)
    print(f"saved detector -> {args.out}")


if __name__ == "__main__":
    main()