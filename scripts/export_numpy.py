#!/usr/bin/env python3
"""
scripts/export_numpy.py — export the trained detector to a torch-free NumPy bundle.

Training needs PyTorch; *serving* does not. The autoencoder is four dense layers —
a forward pass is four matmuls and two ReLUs, which NumPy does fine. Exporting the
weights lets the public scanner run without shipping a 1.5 GB deep-learning runtime
to score a 7 KB model.

  ml/models/detector.pt  ->  ml/models/detector.npz
"""
from __future__ import annotations

import argparse

import numpy as np
import torch


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", default="ml/models/detector.pt")
    ap.add_argument("--out", dest="dst", default="ml/models/detector.npz")
    args = ap.parse_args()

    b = torch.load(args.src, weights_only=False)
    sd = b["state_dict"]

    # encoder: Linear(20,12) -> ReLU -> Linear(12,6) -> ReLU
    # decoder: Linear(6,12)  -> ReLU -> Linear(12,20)
    payload = {
        "enc0_w": sd["encoder.0.weight"].numpy(),
        "enc0_b": sd["encoder.0.bias"].numpy(),
        "enc2_w": sd["encoder.2.weight"].numpy(),
        "enc2_b": sd["encoder.2.bias"].numpy(),
        "dec0_w": sd["decoder.0.weight"].numpy(),
        "dec0_b": sd["decoder.0.bias"].numpy(),
        "dec2_w": sd["decoder.2.weight"].numpy(),
        "dec2_b": sd["decoder.2.bias"].numpy(),
        "mean": np.asarray(b["mean"], dtype=np.float32),
        "std": np.asarray(b["std"], dtype=np.float32),
        "threshold": np.asarray([b["threshold"]], dtype=np.float32),
        "feature_names": np.asarray(b["feature_names"]),
    }
    np.savez(args.dst, **payload)
    print(f"exported -> {args.dst}")
    print(f"  threshold {float(b['threshold']):.5f}  features {b['n_features']}")
    for k, v in payload.items():
        if hasattr(v, "shape") and k not in ("feature_names",):
            print(f"  {k:14s} {v.shape}")


if __name__ == "__main__":
    main()