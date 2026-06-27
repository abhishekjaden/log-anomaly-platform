import os
import tempfile

from services.results.db import connect, init_db, insert_verdict, stats, recent_anomalies


def _fresh_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = connect(path)
    init_db(conn)
    return conn, path


def test_insert_and_stats():
    conn, path = _fresh_db()
    try:
        insert_verdict(conn, {"offset": 1, "raw": "x", "method": "GET", "path": "/a",
                              "query": "", "status": 200, "score": 0.1,
                              "is_anomaly": False, "threshold": 0.45, "drivers": []})
        insert_verdict(conn, {"offset": 2, "raw": "y", "method": "GET", "path": "/products",
                              "query": "id=1 UNION SELECT", "status": 403, "score": 12.0,
                              "is_anomaly": True, "threshold": 0.45,
                              "drivers": ["n_special", "query_entropy"]})
        conn.commit()
        s = stats(conn)
        assert s["total"] == 2
        assert s["anomalies"] == 1
        assert s["anomaly_rate"] == 0.5
    finally:
        conn.close()
        os.unlink(path)


def test_recent_anomalies_only_flagged():
    conn, path = _fresh_db()
    try:
        insert_verdict(conn, {"path": "/ok", "score": 0.1, "is_anomaly": False, "drivers": []})
        insert_verdict(conn, {"path": "/attack", "score": 9.9, "is_anomaly": True,
                              "drivers": ["n_special"]})
        conn.commit()
        rows = recent_anomalies(conn, limit=10)
        assert len(rows) == 1
        assert rows[0]["path"] == "/attack"
        assert rows[0]["drivers"] == ["n_special"]
    finally:
        conn.close()
        os.unlink(path)