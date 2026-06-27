#!/usr/bin/env python3
"""
services/inference — score featurized records from Kafka with the trained
autoencoder and emit anomaly verdicts.

Reads `parsed-logs` (records carrying a precomputed 20-element feature vector),
scores each with the shared Detector, and publishes a verdict to `results`:
score, is_anomaly, threshold, the driver features, and request context.

  parsed-logs (features)  ->  inference (autoencoder score)  ->  results (verdicts)

The Detector loads ml/models/detector.pt once at startup; we score the features
the ingestion stage already computed (no re-featurizing -> same vector end to end).
"""
from __future__ import annotations

import json
import os

import numpy as np
import torch

from kafka import KafkaConsumer, KafkaProducer

from lap.detector import Detector

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:19092")
IN_TOPIC = os.environ.get("IN_TOPIC", "parsed-logs")
OUT_TOPIC = os.environ.get("OUT_TOPIC", "results")
GROUP_ID = os.environ.get("GROUP_ID", "inference")
MODEL_PATH = os.environ.get("MODEL_PATH", "ml/models/detector.pt")
TOP_K = 3


def score_features(det: Detector, features: list) -> dict:
    """Score a precomputed feature vector -> verdict dict. Pure (no Kafka),
    so it's unit-testable. Mirrors Detector internals but skips re-featurizing."""
    X = np.asarray([features], dtype=np.float32)
    scores, per_feat = det._score(X)
    score = float(scores[0])
    order = np.argsort(per_feat[0])[::-1][:TOP_K]
    drivers = [det.feature_names[k] for k in order]
    return {
        "score": round(score, 5),
        "is_anomaly": bool(score > det.threshold),
        "threshold": det.threshold,
        "drivers": drivers,
    }


def main():
    det = Detector(MODEL_PATH)
    consumer = KafkaConsumer(
        IN_TOPIC,
        bootstrap_servers=BOOTSTRAP,
        group_id=GROUP_ID,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
    )
    producer = KafkaProducer(bootstrap_servers=BOOTSTRAP, linger_ms=50, acks=1)
    print(f"inference: {IN_TOPIC} -> {OUT_TOPIC}  group={GROUP_ID}  threshold={det.threshold:.5f}")
    print("waiting for messages... (Ctrl+C to stop)")

    scored = anomalies = 0
    try:
        for msg in consumer:
            rec = json.loads(msg.value.decode("utf-8"))  # decode inline (avoids deserializer DeprecationWarning)
            verdict = score_features(det, rec["features"])
            r = rec.get("record", {})
            out = {
                "offset": rec.get("offset"),
                "raw": rec.get("raw"),
                "method": r.get("method"),
                "path": r.get("path"),
                "query": r.get("query"),
                "status": r.get("status"),
                **verdict,
            }
            producer.send(OUT_TOPIC, value=json.dumps(out).encode("utf-8"))
            scored += 1
            if verdict["is_anomaly"]:
                anomalies += 1
                print(f"  [ANOMALY] score {verdict['score']:.2f}  {out['method']} {out['path']}  <- {', '.join(verdict['drivers'])}")
            if scored % 200 == 0:
                print(f"  scored {scored}  (anomalies {anomalies})")
    except KeyboardInterrupt:
        print("\ninterrupted")
    finally:
        producer.flush()
        producer.close()
        consumer.close()
        print(f"inference stopped. scored={scored} anomalies={anomalies}")


if __name__ == "__main__":
    main()