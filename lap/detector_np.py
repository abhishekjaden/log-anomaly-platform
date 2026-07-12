#!/usr/bin/env python3
"""
lap.detector_np — torch-free detector for the serving path.

Same scoring semantics as lap.detector, but loads the exported NumPy bundle and
runs the forward pass with matmuls instead of PyTorch. Training still uses torch;
serving doesn't need it. This keeps the public scanner image small and fast to start.

Architecture (must match lap.model.AutoEncoder):
  20 -> Linear -> ReLU -> 12 -> Linear -> ReLU -> 6      (encoder)
   6 -> Linear -> ReLU -> 12 -> Linear      -> 20        (decoder)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

import numpy as np

from lap.parser import parse_line
from lap.features import featurize


@dataclass
class ScanResult:
    line_no: int
    is_anomaly: bool
    score: float
    threshold: float
    method: str
    path: str
    query: str
    status: int
    top_features: List[dict] = field(default_factory=list)
    raw: str = ""


def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(x, 0.0)


class NumpyDetector:
    """Loads ml/models/detector.npz and scores combined-format log lines."""

    def __init__(self, bundle_path: str = "ml/models/detector.npz"):
        if not os.path.exists(bundle_path):
            raise FileNotFoundError(
                f"{bundle_path} not found — run scripts/export_numpy.py after training"
            )
        z = np.load(bundle_path, allow_pickle=True)
        self.w = {k: z[k].astype(np.float32) for k in
                  ("enc0_w", "enc0_b", "enc2_w", "enc2_b",
                   "dec0_w", "dec0_b", "dec2_w", "dec2_b")}
        self.mean = z["mean"].astype(np.float32)
        self.std = z["std"].astype(np.float32)
        self.threshold = float(z["threshold"][0])
        self.feature_names = [str(x) for x in z["feature_names"]]

    def _forward(self, Xn: np.ndarray) -> np.ndarray:
        """Reconstruct standardized inputs. Linear weights are (out, in) -> use x @ W.T"""
        h = _relu(Xn @ self.w["enc0_w"].T + self.w["enc0_b"])
        h = _relu(h @ self.w["enc2_w"].T + self.w["enc2_b"])
        h = _relu(h @ self.w["dec0_w"].T + self.w["dec0_b"])
        return h @ self.w["dec2_w"].T + self.w["dec2_b"]

    def _score(self, X: np.ndarray):
        Xn = ((X - self.mean) / self.std).astype(np.float32)
        recon = self._forward(Xn)
        per_feature_err = (recon - Xn) ** 2
        return per_feature_err.mean(axis=1), per_feature_err

    def score_lines(self, lines, top_k: int = 3) -> List[ScanResult]:
        recs, idxs, raws = [], [], []
        for i, line in enumerate(lines, start=1):
            rec = parse_line(line)
            if rec is None:
                continue
            recs.append(rec); idxs.append(i); raws.append(line.rstrip("\r\n"))
        if not recs:
            return []
        X = np.asarray([featurize(r) for r in recs], dtype=np.float32)
        scores, per_feat = self._score(X)
        out = []
        for j, rec in enumerate(recs):
            order = np.argsort(per_feat[j])[::-1][:top_k]
            top = [{"feature": self.feature_names[k],
                    "contribution": round(float(per_feat[j][k]), 4)} for k in order]
            out.append(ScanResult(
                line_no=idxs[j],
                is_anomaly=bool(scores[j] > self.threshold),
                score=round(float(scores[j]), 5),
                threshold=self.threshold,
                method=rec.method, path=rec.path, query=rec.query, status=rec.status,
                top_features=top, raw=raws[j],
            ))
        return out