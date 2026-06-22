#!/usr/bin/env python3
"""
lap.parser — parse nginx/Apache Combined Log Format access logs into structured records.

Combined Log Format:
  IP ident user [time] "METHOD target PROTO" status bytes "referer" "user_agent"

This module is shared by the ingestion (training) and inference (scoring) paths, so
a model trained on one corpus scores any uploaded combined-format log through the
exact same structured representation -- no feature drift between train and serve.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Iterator, Optional
from urllib.parse import urlsplit

# combined-log timestamp, e.g. 22/May/2025:10:55:22 +0000
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

_COMBINED_RE = re.compile(
    r'(?P<ip>\S+) '
    r'(?P<ident>\S+) '
    r'(?P<user>\S+) '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) '
    r'(?P<bytes>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'  # optional -> handles plain "common" format too
)


@dataclass
class LogRecord:
    ip: str
    user: str
    timestamp: Optional[datetime]
    method: str
    path: str
    query: str
    protocol: str
    status: int
    bytes: int
    referer: str
    user_agent: str
    raw: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return d


def _parse_request(request: str):
    parts = request.split(" ")
    if len(parts) >= 3:
        method, target, protocol = parts[0], parts[1], parts[-1]
    elif len(parts) == 2:
        method, target, protocol = parts[0], parts[1], ""
    elif len(parts) == 1 and parts[0]:
        method, target, protocol = parts[0], "", ""
    else:
        method = target = protocol = ""
    split = urlsplit(target)
    return method, (split.path or target), split.query, protocol


def parse_line(line: str) -> Optional[LogRecord]:
    line = line.rstrip("\r\n")
    m = _COMBINED_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    try:
        ts = datetime.strptime(g["time"], _TIME_FMT)
    except (ValueError, TypeError):
        ts = None
    method, path, query, protocol = _parse_request(g["request"])
    raw_bytes = g["bytes"]
    nbytes = int(raw_bytes) if raw_bytes.isdigit() else 0
    return LogRecord(
        ip=g["ip"], user=g["user"], timestamp=ts,
        method=method, path=path, query=query, protocol=protocol,
        status=int(g["status"]), bytes=nbytes,
        referer=g.get("referer") or "", user_agent=g.get("ua") or "",
        raw=line,
    )


def parse_file(path: str) -> Iterator[LogRecord]:
    """Yield a LogRecord per parseable line; silently skips unparseable lines."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            rec = parse_line(line)
            if rec is not None:
                yield rec


def _selfcheck(path: str) -> None:
    total = parsed = 0
    samples = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            total += 1
            rec = parse_line(line)
            if rec is not None:
                parsed += 1
                if len(samples) < 3:
                    samples.append(rec)
    print(f"file:   {path}")
    print(f"total:  {total}")
    print(f"parsed: {parsed}  ({total - parsed} failed)")
    print("--- sample structured records ---")
    for r in samples:
        d = r.to_dict(); d.pop("raw")
        print(d)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "data/sample/access_mixed.log"
    _selfcheck(target)
