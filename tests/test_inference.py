import os
import pytest

from lap.detector import Detector
from services.inference.main import score_features

MODEL = "ml/models/detector.pt"
pytestmark = pytest.mark.skipif(not os.path.exists(MODEL), reason="train a model first")


def _det():
    return Detector(MODEL)


def test_normal_features_not_flagged():
    det = _det()
    # plain GET /index.html style vector (low special chars, normal entropy)
    feats = [11.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 3.46, 0.0, 0.0,
             1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 7.30, 107.0, 0.0]
    v = score_features(det, feats)
    assert v["is_anomaly"] is False
    assert len(v["drivers"]) == 3


def test_attack_features_flagged():
    det = _det()
    # SQLi-like vector: long query, many special chars, suspicious tokens, tool UA
    feats = [9.0, 58.0, 1.0, 6.0, 0.09, 5.0, 11.0, 3.17, 4.65, 3.0,
             1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 6.72, 20.0, 1.0]
    v = score_features(det, feats)
    assert v["is_anomaly"] is True