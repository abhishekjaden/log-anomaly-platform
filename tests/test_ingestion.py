from services.ingestion.main import to_record


def test_to_record_parses_and_featurizes():
    line = ('1.2.3.4 - - [01/Jun/2026:08:00:10 +0000] '
            '"GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"')
    r = to_record(line, offset=5)
    assert r is not None
    assert r["offset"] == 5
    assert r["record"]["method"] == "GET"
    assert r["record"]["path"] == "/index.html"
    assert len(r["features"]) == 20


def test_to_record_skips_malformed():
    assert to_record("not a log line") is None