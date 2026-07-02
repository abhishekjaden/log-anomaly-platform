#!/usr/bin/env python3
"""
scripts/kinesis_produce.py — write access-log lines into an Amazon Kinesis stream.

Phase 2 cloud ingress: the managed-service counterpart to the local Kafka producer.
Reads a combined-format log file and puts each line as a Kinesis record, keyed by
client IP so a given source lands on a consistent shard.
"""
from __future__ import annotations

import argparse
import time

import boto3

from lap.parser import parse_line


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stream", default="lap-access-logs")
    ap.add_argument("--file", default="data/sample/access_mixed.log")
    ap.add_argument("--region", default="ap-south-1")
    ap.add_argument("--limit", type=int, default=50, help="max lines to send (keep small for the demo)")
    args = ap.parse_args()

    client = boto3.client("kinesis", region_name=args.region)
    sent = 0
    with open(args.file, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            rec = parse_line(line)
            key = rec.ip if rec else "unknown"      # partition key -> shard routing
            client.put_record(
                StreamName=args.stream,
                Data=(line + "\n").encode("utf-8"),
                PartitionKey=key,
            )
            sent += 1
            if sent % 10 == 0:
                print(f"  sent {sent}")
            if sent >= args.limit:
                break
            time.sleep(0.05)
    print(f"done. sent {sent} records to {args.stream}")


if __name__ == "__main__":
    main()