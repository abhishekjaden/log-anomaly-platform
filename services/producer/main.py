#!/usr/bin/env python3
"""
services/producer — replay an access log into Kafka as a live stream.

Reads a combined-format access log line by line and publishes each line to the
`access-logs` topic at a controlled rate, simulating live web-server traffic.
This is the head of the streaming pipeline; ingestion consumes from here.

Connects to the host-facing Kafka listener (localhost:19092 by default).
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from kafka import KafkaProducer

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:19092")
TOPIC = os.environ.get("TOPIC", "access-logs")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="data/sample/access_mixed.log",
                    help="access log to replay")
    ap.add_argument("--rate", type=float, default=20.0,
                    help="lines per second (0 = as fast as possible)")
    ap.add_argument("--loop", action="store_true",
                    help="replay forever (for load/streaming demos)")
    args = ap.parse_args()

    if not os.path.exists(args.file):
        sys.exit(f"log file not found: {args.file}")

    # encode to bytes ourselves (no value_serializer) -> avoids the kafka-python
    # 3.x DeprecationWarning about serializers not implementing kafka.serializer.Serializer
    producer = KafkaProducer(
        bootstrap_servers=BOOTSTRAP,
        linger_ms=50,
        acks=1,
    )
    print(f"producer -> {BOOTSTRAP} topic={TOPIC} file={args.file} rate={args.rate}/s loop={args.loop}")

    delay = (1.0 / args.rate) if args.rate > 0 else 0.0
    sent = 0
    try:
        while True:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\r\n")
                    if not line:
                        continue
                    producer.send(TOPIC, value=line.encode("utf-8"))  # encode inline
                    sent += 1
                    if sent % 100 == 0:
                        print(f"  sent {sent} lines")
                    if delay:
                        time.sleep(delay)
            if not args.loop:
                break
    except KeyboardInterrupt:
        print("\ninterrupted")
    finally:
        producer.flush()
        producer.close()
        print(f"done. total sent: {sent}")


if __name__ == "__main__":
    main()