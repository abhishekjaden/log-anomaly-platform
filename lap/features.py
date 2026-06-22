#!/usr/bin/env python3
"""
lap.features — turn a parsed LogRecord into a fixed-length numeric feature vector.

Shared by the training path (ingestion) and the scoring path (inference) so the
exact same representation is used end to end -- no feature drift, same reason the
parser is shared. Features are hand-crafted structural/statistical signals of an
HTTP request: interpretable, cheap, and effective at separating normal browsing
from web attacks (XSS, SQLi, traversal, scanners).
"""
from __future__ import annotations

import math
from typing import List

from lap.parser import LogRecord

_SUSPICIOUS_TOKENS = (
    "script", "alert", "onerror", "onload", "svg", "iframe",      # XSS
    "select", "union", "insert", "drop", "--", "' or", "1=1",      # SQLi
    "../", "..\\", "/etc/passwd", "cmd=", "exec",                  # traversal / RCE
)
_SPECIAL_CHARS = set("<>\"'%(){}[];|&$=*`\\")
_TOOL_UA = ("sqlmap", "nikto", "nmap", "masscan", "curl", "wget",
            "python-requests", "go-http-client", "hydra", "dirbuster")

# stable feature order — also the column names used in the scan report
FEATURE_NAMES: List[str] = [
    "path_len", "query_len", "n_path_segments",
    "n_special", "special_ratio", "n_percent", "n_digits",
    "path_entropy", "query_entropy",
    "n_suspicious_tokens",
    "is_get", "is_post", "is_other_method",
    "is_2xx", "is_3xx", "is_4xx", "is_5xx",
    "log_bytes", "ua_len", "ua_is_tool",
]
N_FEATURES = len(FEATURE_NAMES)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def featurize(rec: LogRecord) -> List[float]:
    path = rec.path or ""
    query = rec.query or ""
    pq = path + query
    ua = (rec.user_agent or "").lower()
    blob = pq.lower()

    n_special = sum(1 for ch in pq if ch in _SPECIAL_CHARS)
    total = len(pq) or 1
    method = (rec.method or "").upper()
    status = rec.status or 0

    feats = [
        float(len(path)),
        float(len(query)),
        float(path.count("/")),
        float(n_special),
        n_special / total,
        float(pq.count("%")),
        float(sum(ch.isdigit() for ch in pq)),
        _entropy(path),
        _entropy(query),
        float(sum(blob.count(tok) for tok in _SUSPICIOUS_TOKENS)),
        1.0 if method == "GET" else 0.0,
        1.0 if method == "POST" else 0.0,
        0.0 if method in ("GET", "POST") else 1.0,
        1.0 if 200 <= status < 300 else 0.0,
        1.0 if 300 <= status < 400 else 0.0,
        1.0 if 400 <= status < 500 else 0.0,
        1.0 if 500 <= status < 600 else 0.0,
        math.log1p(max(rec.bytes, 0)),
        float(len(ua)),
        1.0 if any(t in ua for t in _TOOL_UA) else 0.0,
    ]
    assert len(feats) == N_FEATURES
    return feats


if __name__ == "__main__":
    import sys
    from lap.parser import parse_file
    target = sys.argv[1] if len(sys.argv) > 1 else "data/sample/access_mixed.log"
    print(",".join(FEATURE_NAMES))
    for i, rec in enumerate(parse_file(target)):
        if i >= 5:
            break
        print([round(x, 3) for x in featurize(rec)])