#!/usr/bin/env python3
"""
services/results/api — read API over the stored verdicts.

Serves the streamed anomaly history the pipeline accumulated, so the frontend can
show recent anomalies + summary stats (vs. the upload-based scan API).

  GET /health
  GET /stats                 -> totals + anomaly rate
  GET /anomalies?limit=50    -> recent anomalies, newest first
"""
from __future__ import annotations

from fastapi import FastAPI, Query

from services.results.db import connect, init_db, stats, recent_anomalies

app = FastAPI(title="Results API", version="0.1.0")


def _conn():
    conn = connect()
    init_db(conn)
    return conn


@app.get("/health")
def health():
    conn = _conn()
    try:
        return {"status": "ok", "stored": stats(conn)["total"]}
    finally:
        conn.close()


@app.get("/stats")
def get_stats():
    conn = _conn()
    try:
        return stats(conn)
    finally:
        conn.close()


@app.get("/anomalies")
def get_anomalies(limit: int = Query(50, ge=1, le=500)):
    conn = _conn()
    try:
        return {"anomalies": recent_anomalies(conn, limit)}
    finally:
        conn.close()