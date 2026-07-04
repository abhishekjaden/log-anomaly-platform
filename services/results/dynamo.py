#!/usr/bin/env python3
"""
services/results/dynamo — DynamoDB persistence for scored verdicts.

Cloud counterpart to services/results/db.py (SQLite). Same shape of operations
(insert a verdict, fetch recent anomalies, summary stats) against a managed table.
All rows share one partition key ("verdict") and sort by a numeric id, mirroring the
local "ORDER BY id DESC" access pattern at this scale.

Table: lap-verdicts  (pk: S = "verdict", id: N)
"""
from __future__ import annotations

import os
import time
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key

TABLE = os.environ.get("VERDICTS_TABLE", "lap-verdicts")
REGION = os.environ.get("AWS_REGION", "ap-south-1")
PK = "verdict"


def _table():
    return boto3.resource("dynamodb", region_name=REGION).Table(TABLE)


def _next_id() -> int:
    # monotonic-ish id from time; fine for a single-writer demo
    return int(time.time() * 1000)


def put_verdict(v: dict, table=None) -> int:
    """Write one verdict. Floats -> Decimal (DynamoDB rejects float). Returns the id."""
    t = table or _table()
    vid = _next_id()
    item = {
        "pk": PK,
        "id": vid,
        "raw": v.get("raw"),
        "method": v.get("method"),
        "path": v.get("path"),
        "query": v.get("query"),
        "status": v.get("status"),
        "score": Decimal(str(v.get("score", 0.0))),
        "is_anomaly": bool(v.get("is_anomaly")),
        "threshold": Decimal(str(v.get("threshold", 0.0))),
        "drivers": v.get("drivers", []),
    }
    t.put_item(Item=item)
    return vid


def recent_anomalies(limit: int = 50, table=None) -> list:
    """Most recent flagged verdicts, newest first."""
    t = table or _table()
    resp = t.query(
        KeyConditionExpression=Key("pk").eq(PK),
        FilterExpression="is_anomaly = :true",
        ExpressionAttributeValues={":true": True},
        ScanIndexForward=False,   # descending by id
        Limit=limit * 4,          # over-fetch since filter runs after the limit
    )
    items = resp.get("Items", [])[:limit]
    for it in items:             # Decimal -> float for JSON friendliness
        it["score"] = float(it.get("score", 0))
        it["threshold"] = float(it.get("threshold", 0))
    return items


def stats(table=None) -> dict:
    """Totals + anomaly rate. Scans the partition; fine at demo scale."""
    t = table or _table()
    resp = t.query(KeyConditionExpression=Key("pk").eq(PK))
    items = resp.get("Items", [])
    total = len(items)
    anomalies = sum(1 for it in items if it.get("is_anomaly"))
    return {
        "total": total,
        "anomalies": anomalies,
        "anomaly_rate": round(anomalies / total, 4) if total else 0.0,
    }


if __name__ == "__main__":
    # smoke test: write a normal + an attack, then read stats and anomalies
    put_verdict({"raw": "x", "method": "GET", "path": "/index.html", "query": "",
                 "status": 200, "score": 0.10, "is_anomaly": False,
                 "threshold": 0.4535, "drivers": ["log_bytes"]})
    put_verdict({"raw": "y", "method": "GET", "path": "/products",
                 "query": "id=1 UNION SELECT", "status": 403, "score": 12.4,
                 "is_anomaly": True, "threshold": 0.4535,
                 "drivers": ["n_special", "query_entropy"]})
    print("stats:", stats())
    print("recent anomalies:")
    for a in recent_anomalies(5):
        print(f"  score {a['score']:.2f}  {a['method']} {a['path']}  <- {', '.join(a.get('drivers', []))}")