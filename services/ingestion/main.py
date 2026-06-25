#!/usr/bin/env python3
"""
services/ingestion — consume raw access-log lines from Kafka, parse + featurize
them with the shared `lap` code, and emit structured + featurized records to the
`parsed-logs` topic for the inference service.

First consumer in the pipeline. Uses a consumer group, so the work parallelizes
across instances later (group members map to Kinesis shards in the cloud phase).

  access-logs (raw)  ->  ingestion (parse + featurize)  ->  parsed-logs (json)
"""
from __future__ import annotations

import json
import os
from typing import Optional

from kafka import KafkaConsumer, KafkaProducer

from lap.parser import parse_line
from lap.features import featurize

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:19092")
IN_TOPIC = os.environ.get("IN_TOPIC", "access-logs")
OUT_TOPIC = os.environ.get("OUT_TOPIC", "parsed-logs")
GROUP_ID = os.environ.get("GROUP_ID", "ingestion")


def to_record(raw: str, offset: Optional[int] = None) -> Optional[dict]:
    """Parse + featurize one raw log line into the structured record we emit.
    Returns None for unparseable lines. Pure function -> unit-testable without Kafka."""
    rec = parse_line(raw)
    if rec is None:
        return None
    return {
        "offset": offset,
        "raw": raw,
        "record": rec.to_dict(),
        "features": featurize(rec),
    }


def main():
    consumer = KafkaConsumer(
        IN_TOPIC,
        bootstrap_servers=BOOTSTRAP,
        group_id=GROUP_ID,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
    )
    producer = KafkaProducer(bootstrap_servers=BOOTSTRAP, linger_ms=50, acks=1)
    print(f"ingestion: {IN_TOPIC} -> {OUT_TOPIC}  group={GROUP_ID}  broker={BOOTSTRAP}")
    print("waiting for messages... (Ctrl+C to stop)")

    consumed = parsed = skipped = 0
    try:
        for msg in consumer:
            consumed += 1
            raw = msg.value.decode("utf-8", errors="replace")
            out = to_record(raw, offset=msg.offset)
            if out is None:
                skipped += 1
                continue
            producer.send(OUT_TOPIC, value=json.dumps(out).encode("utf-8"))
            parsed += 1
            if parsed % 100 == 0:
                print(f"  parsed {parsed}  (skipped {skipped})")
    except KeyboardInterrupt:
        print("\ninterrupted")
    finally:
        producer.flush()
        producer.close()
        consumer.close()
        print(f"ingestion stopped. consumed={consumed} parsed={parsed} skipped={skipped}")


if __name__ == "__main__":
    main()