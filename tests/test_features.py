from lap.parser import parse_line
from lap.features import featurize, FEATURE_NAMES, N_FEATURES


def _rec(line):
    rec = parse_line(line)
    assert rec is not None
    return rec


def test_vector_length_matches_names():
    rec = _rec('1.2.3.4 - - [01/Jun/2026:08:00:10 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"')
    assert len(featurize(rec)) == N_FEATURES == len(FEATURE_NAMES)


def test_attack_scores_higher_on_structure():
    normal = _rec('1.2.3.4 - - [01/Jun/2026:08:00:10 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"')
    attack = _rec('1.2.3.4 - - [01/Jun/2026:08:00:11 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "sqlmap/1.8"')
    fn = dict(zip(FEATURE_NAMES, featurize(normal)))
    fa = dict(zip(FEATURE_NAMES, featurize(attack)))
    assert fa["n_special"] > fn["n_special"]
    assert fa["n_suspicious_tokens"] > fn["n_suspicious_tokens"]
    assert fa["ua_is_tool"] == 1.0 and fn["ua_is_tool"] == 0.0


def test_method_and_status_onehot():
    rec = _rec('1.2.3.4 - - [01/Jun/2026:08:00:10 +0000] "POST /login HTTP/1.1" 404 10 "-" "curl/8.0"')
    f = dict(zip(FEATURE_NAMES, featurize(rec)))
    assert f["is_post"] == 1.0 and f["is_get"] == 0.0
    assert f["is_4xx"] == 1.0 and f["is_2xx"] == 0.0