"""
End-to-end integration test: one raw log line through the whole data contract --
parse -> featurize -> score -> store -> query -- in-process (no Kafka), proving
the stages compose correctly and the representation stays consistent across them.
"""
import os
import tempfile

import pytest

from services.ingestion.main import to_record
from services.inference.main import score_features
from services.results.db import connect, init_db, insert_verdict, stats, recent_anomalies
from lap.detector import Detector

MODEL = "ml/models/detector.pt"
pytestmark = pytest.mark.skipif(not os.path.exists(MODEL), reason="train a model first")

ATTACK = ('9.9.9.9 - - [01/Jun/2026:12:00:00 +0000] '
          '"GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" '
          '403 800 "-" "python-requests/2.31"')
NORMAL = ('1.2.3.4 - - [01/Jun/2026:08:00:10 +0000] '
          '"GET /index.html HTTP/1.1" 200 2326 "https://example.com/" '
          '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"')


def _pipeline(raw, det, conn):
    """Mirror the streaming stages on a single line: ingestion -> inference -> storage."""
    rec = to_record(raw)                      # ingestion: parse + featurize
    assert rec is not None
    verdict = score_features(det, rec["features"])   # inference: score
    r = rec["record"]
    insert_verdict(conn, {                    # storage: persist
        "offset": rec["offset"], "raw": rec["raw"],
        "method": r["method"], "path": r["path"], "query": r["query"], "status": r["status"],
        **verdict,
    })
    conn.commit()
    return verdict


def test_attack_flows_through_and_is_queryable():
    det = Detector(MODEL)
    fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
    conn = connect(path); init_db(conn)
    try:
        v_norm = _pipeline(NORMAL, det, conn)
        v_atk = _pipeline(ATTACK, det, conn)

        # the model separates them
        assert v_norm["is_anomaly"] is False
        assert v_atk["is_anomaly"] is True
        assert v_atk["score"] > v_norm["score"]

        # storage saw both; only the attack is a queryable anomaly
        s = stats(conn)
        assert s["total"] == 2 and s["anomalies"] == 1

        flagged = recent_anomalies(conn, limit=10)
        assert len(flagged) == 1
        assert flagged[0]["path"] == "/products"
        assert "n_special" in flagged[0]["drivers"] or "query_entropy" in flagged[0]["drivers"]
    finally:
        conn.close()
        os.unlink(path)