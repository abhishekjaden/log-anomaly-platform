#!/usr/bin/env python3
"""
Evaluate the trained detector against a labeled mixed corpus.

Loads the detector bundle, scores every parseable line, applies the saved threshold,
and reports precision / recall / F1 and a confusion matrix against ground truth --
plus a few example misses so failures are legible rather than just a number.
"""
from __future__ import annotations

import argparse
import csv

import numpy as np
import torch

from lap.parser import parse_line
from lap.features import featurize
from lap.model import AutoEncoder, reconstruction_error


def load_detector(path):
    # weights_only=False: our own trusted bundle carries numpy arrays + python
    # objects (scaler stats, threshold, feature names), which the torch>=2.6
    # default (weights_only=True) refuses to unpickle.
    b = torch.load(path, weights_only=False)
    model = AutoEncoder(b["n_features"], **b["arch"])
    model.load_state_dict(b["state_dict"])
    model.eval()
    return model, np.asarray(b["mean"]), np.asarray(b["std"]), b["threshold"]


def load_labels(path):
    labels = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            labels[int(row["line_no"])] = int(row["label"])
    return labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="ml/models/detector.pt")
    ap.add_argument("--mixed", default="data/sample/access_mixed.log")
    ap.add_argument("--labels", default="data/sample/access_mixed_labels.csv")
    args = ap.parse_args()

    model, mean, std, thr = load_detector(args.model)
    labels = load_labels(args.labels)

    rows, y_true, raws = [], [], []
    with open(args.mixed, encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            rec = parse_line(line)
            if rec is None or line_no not in labels:
                continue  # keep label alignment by line number
            rows.append(featurize(rec))
            y_true.append(labels[line_no])
            raws.append(line.rstrip("\n"))

    X = ((np.asarray(rows, dtype=np.float32) - mean) / std).astype(np.float32)
    errs = reconstruction_error(model, torch.from_numpy(X)).numpy()
    y_true = np.asarray(y_true)
    y_pred = (errs > thr).astype(int)

    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())

    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0

    print(f"threshold {thr:.5f}   evaluated {len(y_true)} lines")
    print(f"confusion:  TP {tp}  FP {fp}  FN {fn}  TN {tn}")
    print(f"precision {prec:.3f}  recall {rec:.3f}  f1 {f1:.3f}")

    fns = [(errs[i], raws[i]) for i in range(len(y_true)) if y_pred[i] == 0 and y_true[i] == 1]
    fps = [(errs[i], raws[i]) for i in range(len(y_true)) if y_pred[i] == 1 and y_true[i] == 0]
    if fns:
        print("\n-- missed attacks (false negatives), lowest-error first, up to 5 --")
        for e, r in sorted(fns)[:5]:
            print(f"  err {e:.3f}  {r[:120]}")
    if fps:
        print("\n-- flagged normals (false positives), highest-error first, up to 5 --")
        for e, r in sorted(fps, reverse=True)[:5]:
            print(f"  err {e:.3f}  {r[:120]}")


if __name__ == "__main__":
    main()