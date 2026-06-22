#!/usr/bin/env python3
"""
scripts/gen_logs.py — generate realistic nginx/Apache combined-format access logs
for training and evaluation, so the pipeline runs on meaningful volume and anyone
can reproduce the corpus from scratch with a fixed seed.

Outputs (default --out-dir data/sample):
  access_normal.log         normal traffic only            (autoencoder training)
  access_mixed.log          normal + injected attacks      (labeled evaluation)
  access_mixed_labels.csv   line_no,label   (1 = attack)   (eval ground truth)

Synthetic but realistic. NOT a substitute for a real production corpus; the project
is framed accordingly. It exists to exercise the detection pipeline reproducibly.
"""
from __future__ import annotations

import argparse
import csv
import os
import random
from datetime import datetime, timedelta, timezone

_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36",
]
_TOOL_UAS = ["sqlmap/1.8", "Nikto/2.5.0", "python-requests/2.31", "curl/8.6.0", "Go-http-client/1.1"]

_NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/login", "/account",
    "/blog/how-to-cook-rice", "/blog/best-laptops-2026", "/products/1042",
    "/products/2381", "/static/app.css", "/static/main.js", "/favicon.ico",
    "/api/v1/products", "/api/v1/cart",
]
_SEARCH_TERMS = ["headphones", "laptop", "running+shoes", "coffee+maker", "books"]
_REFERERS = ["-", "https://www.google.com/", "https://www.bing.com/search",
             "https://example.com/", "https://t.co/abc"]

_ATTACKS = [  # (path, query)
    ("/search", "q=<script>alert(1)</script>"),
    ("/profile", "name=<svg/onload=alert(1)>"),
    ("/products", "id=1' OR '1'='1"),
    ("/products", "id=1 UNION SELECT username,password FROM users--"),
    ("/download", "file=../../../../etc/passwd"),
    ("/api/v1/exec", "cmd=;cat /etc/passwd"),
    ("/search", "q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"),
    ("/login", "user=admin'--&pass=x"),
]


def _fmt_time(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S %z")


def _rand_ip(rng: random.Random) -> str:
    return ".".join(str(rng.randint(1, 254)) for _ in range(4))


def _normal_line(rng: random.Random, dt: datetime) -> str:
    ip = _rand_ip(rng)
    method = rng.choices(["GET", "POST"], weights=[85, 15])[0]
    if rng.random() < 0.25:
        target = f"/search?q={rng.choice(_SEARCH_TERMS)}"
    else:
        target = rng.choice(_NORMAL_PATHS)
    status = rng.choices([200, 304, 404, 301], weights=[88, 5, 5, 2])[0]
    nbytes = 0 if status == 304 else rng.randint(120, 9000)
    ua = rng.choice(_UAS)
    ref = rng.choice(_REFERERS)
    return (f'{ip} - - [{_fmt_time(dt)}] "{method} {target} HTTP/1.1" '
            f'{status} {nbytes if nbytes else "-"} "{ref}" "{ua}"')


def _attack_line(rng: random.Random, dt: datetime) -> str:
    ip = _rand_ip(rng)
    path, query = rng.choice(_ATTACKS)
    target = f"{path}?{query}"
    status = rng.choice([200, 400, 403, 500])
    nbytes = rng.randint(0, 1500)
    ua = rng.choice(_TOOL_UAS + _UAS)  # attackers sometimes spoof real UAs
    return (f'{ip} - - [{_fmt_time(dt)}] "GET {target} HTTP/1.1" '
            f'{status} {nbytes if nbytes else "-"} "-" "{ua}"')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-normal", type=int, default=5000)
    ap.add_argument("--n-attacks", type=int, default=250)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out-dir", default="data/sample")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    os.makedirs(args.out_dir, exist_ok=True)
    start = datetime(2026, 6, 1, 8, 0, 0, tzinfo=timezone.utc)

    # 1. normal-only training corpus
    t = start
    with open(os.path.join(args.out_dir, "access_normal.log"), "w", encoding="utf-8") as f:
        for _ in range(args.n_normal):
            f.write(_normal_line(rng, t) + "\n")
            t += timedelta(seconds=rng.randint(1, 5))

    # 2. mixed corpus + aligned labels
    entries = []
    t = start
    for _ in range(args.n_normal):
        entries.append((_normal_line(rng, t), 0)); t += timedelta(seconds=rng.randint(1, 5))
    for _ in range(args.n_attacks):
        entries.append((_attack_line(rng, t), 1)); t += timedelta(seconds=rng.randint(1, 5))
    rng.shuffle(entries)

    mixed_path = os.path.join(args.out_dir, "access_mixed.log")
    labels_path = os.path.join(args.out_dir, "access_mixed_labels.csv")
    with open(mixed_path, "w", encoding="utf-8") as flog, \
         open(labels_path, "w", encoding="utf-8", newline="") as fcsv:
        w = csv.writer(fcsv)
        w.writerow(["line_no", "label"])
        for i, (line, label) in enumerate(entries, start=1):
            flog.write(line + "\n")
            w.writerow([i, label])

    total = args.n_normal + args.n_attacks
    print(f"wrote {args.n_normal} normal lines -> {args.out_dir}/access_normal.log")
    print(f"wrote {total} mixed lines ({args.n_attacks} attacks) -> {mixed_path}")
    print(f"wrote labels -> {labels_path}")


if __name__ == "__main__":
    main()