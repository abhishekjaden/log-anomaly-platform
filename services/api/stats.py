#!/usr/bin/env python3
"""
services/api/stats — durable usage counters in DynamoDB.

Tracks aggregate usage (scans run, lines processed, anomalies flagged, rough unique
visitors) so real usage survives App Runner restarts. Stores ONLY tallies and salted
IP *hashes* — never log contents, never raw IPs.

Table: lap-usage  (pk: S)
  - item pk="totals"   holds the running counters
  - items pk="v#<hash>" mark seen visitors (for a unique-ish count)
"""
from __future__ import annotations

import hashlib
import os

import boto3
from boto3.dynamodb.conditions import Key

TABLE = os.environ.get("USAGE_TABLE", "lap-usage")
REGION = os.environ.get("AWS_REGION", "ap-south-1")
SALT = os.environ.get("USAGE_SALT", "logscan-v1")
_ENABLED = os.environ.get("USAGE_TRACKING", "1") == "1"


def _table():
    return boto3.resource("dynamodb", region_name=REGION).Table(TABLE)


def _hash_ip(ip: str) -> str:
    return hashlib.sha256((SALT + "|" + (ip or "unknown")).encode()).hexdigest()[:32]


def record_scan(lines: int, anomalies: int, client_ip: str = "") -> None:
    """Increment counters + mark visitor. Never raises into the request path."""
    if not _ENABLED:
        return
    try:
        t = _table()
        t.update_item(
            Key={"pk": "totals"},
            UpdateExpression="ADD scans_run :one, lines_processed :l, anomalies_flagged :a",
            ExpressionAttributeValues={":one": 1, ":l": lines, ":a": anomalies},
        )
        vh = _hash_ip(client_ip)
        t.put_item(Item={"pk": f"v#{vh}"})
    except Exception:
        pass  # analytics must never break a scan


def get_totals() -> dict:
    """Read the running totals + unique-visitor count."""
    try:
        t = _table()
        row = t.get_item(Key={"pk": "totals"}).get("Item", {})
        visitors = 0
        resp = t.scan(FilterExpression=Key("pk").begins_with("v#"),
                      ProjectionExpression="pk")
        visitors += len(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = t.scan(FilterExpression=Key("pk").begins_with("v#"),
                          ProjectionExpression="pk",
                          ExclusiveStartKey=resp["LastEvaluatedKey"])
            visitors += len(resp.get("Items", []))
        return {
            "scans_run": int(row.get("scans_run", 0)),
            "lines_processed": int(row.get("lines_processed", 0)),
            "anomalies_flagged": int(row.get("anomalies_flagged", 0)),
            "unique_visitors": visitors,
        }
    except Exception as e:
        return {"error": str(e)}