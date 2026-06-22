from datetime import datetime
from lap.parser import parse_line


def test_parses_normal_line():
    line = ('203.0.113.5 - - [01/Jun/2026:08:00:10 +0000] '
            '"GET /index.html HTTP/1.1" 200 2326 "https://example.com/" "Mozilla/5.0"')
    rec = parse_line(line)
    assert rec is not None
    assert rec.ip == "203.0.113.5"
    assert rec.method == "GET"
    assert rec.path == "/index.html"
    assert rec.query == ""
    assert rec.status == 200
    assert rec.bytes == 2326
    assert rec.user_agent == "Mozilla/5.0"
    assert isinstance(rec.timestamp, datetime)


def test_splits_path_and_query_on_attack():
    line = ('198.51.100.7 - - [01/Jun/2026:08:01:00 +0000] '
            '"GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "sqlmap/1.8"')
    rec = parse_line(line)
    assert rec is not None
    assert rec.path == "/search"
    assert "<script>" in rec.query
    assert rec.user_agent == "sqlmap/1.8"


def test_bytes_dash_becomes_zero():
    line = '10.0.0.1 - - [01/Jun/2026:08:02:00 +0000] "GET / HTTP/1.1" 304 - "-" "curl/8.0"'
    rec = parse_line(line)
    assert rec is not None
    assert rec.bytes == 0


def test_malformed_lines_return_none():
    assert parse_line("this is not a log line") is None
    assert parse_line("") is None
