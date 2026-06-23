import os
import pytest
from fastapi.testclient import TestClient

MODEL = "ml/models/detector.pt"
pytestmark = pytest.mark.skipif(not os.path.exists(MODEL), reason="train a model first")


def _client():
    from services.api.main import app
    return TestClient(app)


def test_index_served():
    r = _client().get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


def test_health():
    r = _client().get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_scan_flags_attack():
    log = (
        '1.2.3.4 - - [01/Jun/2026:08:00:10 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"\n'
        '1.2.3.4 - - [01/Jun/2026:08:00:11 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "sqlmap/1.8"\n'
    )
    r = _client().post("/scan", files={"file": ("test.log", log, "text/plain")})
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["parsed"] == 2
    assert body["summary"]["anomalies"] == 1
    assert body["anomalies"][0]["path"] == "/search"