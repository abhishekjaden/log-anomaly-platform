#!/usr/bin/env python3
"""
services/api — FastAPI scan service.

POST a combined-format access log; get back a structured scan report: summary stats
plus the flagged anomalies and the features that drove each flag. This is the
user-facing surface -- the endpoint a real user (or the frontend) hits to scan logs.
"""
from __future__ import annotations

import os
from functools import lru_cache

from fastapi import FastAPI, UploadFile, File, HTTPException

from lap.detector import Detector

MODEL_PATH = os.environ.get("MODEL_PATH", "ml/models/detector.pt")
MAX_ANOMALIES = 200

app = FastAPI(title="Log Anomaly Scanner", version="0.1.0")


@lru_cache(maxsize=1)
def get_detector() -> Detector:
    return Detector(MODEL_PATH)


@app.get("/health")
def health():
    try:
        d = get_detector()
        return {"status": "ok", "threshold": d.threshold, "features": len(d.feature_names)}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"model not loaded: {e}")


@app.post("/scan")
async def scan(file: UploadFile = File(...)):
    raw = (await file.read()).decode("utf-8", errors="replace")
    lines = raw.splitlines()
    if not lines:
        raise HTTPException(status_code=400, detail="empty upload")

    d = get_detector()
    results = d.score_lines(lines)
    anomalies = sorted((r for r in results if r.is_anomaly), key=lambda r: r.score, reverse=True)

    return {
        "summary": {
            "filename": file.filename,
            "total_lines": len(lines),
            "parsed": len(results),
            "anomalies": len(anomalies),
            "anomaly_rate": round(len(anomalies) / len(results), 4) if results else 0.0,
            "threshold": d.threshold,
        },
        "anomalies": [
            {
                "line_no": r.line_no,
                "score": r.score,
                "method": r.method,
                "path": r.path,
                "query": r.query,
                "status": r.status,
                "drivers": [f["feature"] for f in r.top_features],
            }
            for r in anomalies[:MAX_ANOMALIES]
        ],
        "truncated": len(anomalies) > MAX_ANOMALIES,
    }