import os
import pytest

from lap.detector import Detector

MODEL = "ml/models/detector.pt"


@pytest.mark.skipif(not os.path.exists(MODEL), reason="train a model first (artifact is gitignored)")
def test_flags_attack_not_normal():
    d = Detector(MODEL)
    normal = '1.2.3.4 - - [01/Jun/2026:08:00:10 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'
    attack = '1.2.3.4 - - [01/Jun/2026:08:00:11 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "sqlmap/1.8"'
    res = d.score_lines([normal, attack])
    assert len(res) == 2
    assert res[0].is_anomaly is False
    assert res[1].is_anomaly is True
    assert res[1].score > res[0].score
    assert len(res[1].top_features) == 3