import os
import pytest
import numpy as np

TORCH_MODEL = "ml/models/detector.pt"
NP_MODEL = "ml/models/detector.npz"

pytestmark = pytest.mark.skipif(
    not (os.path.exists(TORCH_MODEL) and os.path.exists(NP_MODEL)),
    reason="train + export first",
)

LINES = [
    '1.2.3.4 - - [01/Jun/2026:08:00:10 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0"',
    '9.9.9.9 - - [01/Jun/2026:12:00:00 +0000] "GET /products?id=1%20UNION%20SELECT%20pass%20FROM%20users-- HTTP/1.1" 403 800 "-" "python-requests/2.31"',
    '8.8.8.8 - - [01/Jun/2026:12:01:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "sqlmap/1.8"',
    '7.7.7.7 - - [01/Jun/2026:12:02:00 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 50 "-" "Nikto/2.5.0"',
]


def test_numpy_matches_torch():
    from lap.detector import Detector
    from lap.detector_np import NumpyDetector

    t = Detector(TORCH_MODEL)
    n = NumpyDetector(NP_MODEL)

    assert abs(t.threshold - n.threshold) < 1e-6
    assert t.feature_names == n.feature_names

    rt = t.score_lines(LINES)
    rn = n.score_lines(LINES)
    assert len(rt) == len(rn) == 4

    for a, b in zip(rt, rn):
        assert a.path == b.path
        assert a.is_anomaly == b.is_anomaly
        assert abs(a.score - b.score) < 1e-4, f"{a.path}: torch {a.score} vs numpy {b.score}"
        assert [f["feature"] for f in a.top_features] == [f["feature"] for f in b.top_features]


def test_numpy_flags_attacks_not_normal():
    from lap.detector_np import NumpyDetector
    n = NumpyDetector(NP_MODEL)
    res = n.score_lines(LINES)
    assert res[0].is_anomaly is False
    assert all(r.is_anomaly for r in res[1:])