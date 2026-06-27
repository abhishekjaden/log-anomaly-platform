#!/usr/bin/env python3
"""
services/results/db — SQLite persistence for scored verdicts.

Local stand-in for DynamoDB/RDS in the cloud phase. Pure storage layer (no Kafka,
no HTTP) so it's unit-testable. The storage consumer writes here; the read API
queries here.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get("RESULTS_DB", "data/results.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT    NOT NULL,
    offset     INTEGER,
    raw        TEXT,
    method     TEXT,
    path       TEXT,
    query      TEXT,
    status     INTEGER,
    score      REAL,
    is_anomaly INTEGER,
    threshold  REAL,
    drivers    TEXT
);
CREATE INDEX IF NOT EXISTS idx_anomaly_score ON verdicts(is_anomaly, score DESC);
CREATE INDEX IF NOT EXISTS idx_id ON verdicts(id DESC);
"""


def connect(path: str = DB_PATH) -> sqlite3.Connection:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # lets the API read while the consumer writes
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    conn.commit()


def insert_verdict(conn: sqlite3.Connection, v: dict) -> None:
    conn.execute(
        "INSERT INTO verdicts (ts, offset, raw, method, path, query, status, score, is_anomaly, threshold, drivers) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            datetime.now(timezone.utc).isoformat(),
            v.get("offset"), v.get("raw"), v.get("method"), v.get("path"),
            v.get("query"), v.get("status"), v.get("score"),
            1 if v.get("is_anomaly") else 0,
            v.get("threshold"),
            json.dumps(v.get("drivers", [])),
        ),
    )


def stats(conn: sqlite3.Connection) -> dict:
    row = conn.execute(
        "SELECT COUNT(*) AS total, COALESCE(SUM(is_anomaly), 0) AS anomalies FROM verdicts"
    ).fetchone()
    total, anomalies = row["total"], row["anomalies"]
    return {
        "total": total,
        "anomalies": anomalies,
        "anomaly_rate": round(anomalies / total, 4) if total else 0.0,
    }


def recent_anomalies(conn: sqlite3.Connection, limit: int = 50) -> list:
    rows = conn.execute(
        "SELECT id, ts, offset, raw, method, path, query, status, score, threshold, drivers "
        "FROM verdicts WHERE is_anomaly = 1 ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["drivers"] = json.loads(d["drivers"]) if d["drivers"] else []
        out.append(d)
    return out