#!/usr/bin/env python3
"""
services/results/consumer — persist scored verdicts from Kafka into SQLite.

Last consumer in the pipeline:
  results (verdicts)  ->  storage consumer  ->  SQLite (queryable by the API)
"""
from __future__ import annotations

import json
import os

from kafka import KafkaConsumer

from services.results.db import connect, init_db, insert_verdict

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:19092")
IN_TOPIC = os.environ.get("IN_TOPIC", "results")
GROUP_ID = os.environ.get("GROUP_ID", "storage")
COMMIT_EVERY = 200


def main():
    conn = connect()
    init_db(conn)
    consumer = KafkaConsumer(
        IN_TOPIC,
        bootstrap_servers=BOOTSTRAP,
        group_id=GROUP_ID,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
    )
    print(f"storage: {IN_TOPIC} -> SQLite  group={GROUP_ID}  broker={BOOTSTRAP}")
    print("waiting for messages... (Ctrl+C to stop)")

    stored = anomalies = 0
    try:
        for msg in consumer:
            v = json.loads(msg.value.decode("utf-8"))
            insert_verdict(conn, v)
            stored += 1
            if v.get("is_anomaly"):
                anomalies += 1
            if stored % COMMIT_EVERY == 0:
                conn.commit()
                print(f"  stored {stored}  (anomalies {anomalies})")
    except KeyboardInterrupt:
        print("\ninterrupted")
    finally:
        conn.commit()
        conn.close()
        consumer.close()
        print(f"storage stopped. stored={stored} anomalies={anomalies}")


if __name__ == "__main__":
    main()