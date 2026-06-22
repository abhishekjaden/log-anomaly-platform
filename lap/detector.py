#!/usr/bin/env python3
"""
lap.detector — load a trained detector bundle and score log lines into scan results.

Shared scoring core for both the inference service and the API. Load the bundle once,
then score any combined-format line. Each result carries the anomaly score, the
verdict, and the top features that drove the score (computed in standardized space) --
so the scan report explains *why* a request was flagged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

import numpy as np
import torch

from lap.parser import parse_line
from lap.features import featurize
from lap.model import AutoEncoder


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


class Detector:
    def __init__(self, bundle_path: str = "ml/models/detector.pt"):
        b = torch.load(bundle_path, weights_only=False)  # trusted local bundle
        self.mean = np.asarray(b["mean"], dtype=np.float32)
        self.std = np.asarray(b["std"], dtype=np.float32)
        self.threshold = float(b["threshold"])
        self.feature_names = b["feature_names"]
        self.model = AutoEncoder(b["n_features"], **b["arch"])
        self.model.load_state_dict(b["state_dict"])
        self.model.eval()

    def _score(self, X: np.ndarray):
        Xn = ((X - self.mean) / self.std).astype(np.float32)
        with torch.no_grad():
            recon = self.model(torch.from_numpy(Xn)).numpy()
        per_feature_err = (recon - Xn) ** 2          # standardized-space error per feature
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


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample/access_mixed.log"
    d = Detector()
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    anomalies = [r for r in d.score_lines(lines) if r.is_anomaly]
    for r in anomalies[:8]:
        drivers = ", ".join(f"{f['feature']}={f['contribution']}" for f in r.top_features)
        print(f"[ANOMALY] score {r.score:.3f}  {r.method} {r.path}?{r.query[:50]}  <- {drivers}")
    print(f"... {len(anomalies)} anomalies flagged of {len(lines)} lines")