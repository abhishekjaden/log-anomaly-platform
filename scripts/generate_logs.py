#!/usr/bin/env python3
"""
generate_logs.py — synthetic web access-log generator (Combined Log Format).

Produces deterministic, labeled nginx/Apache "combined" access logs for local
development and evaluation of the anomaly detector:

  data/sample/access_normal.log   normal traffic only  -> autoencoder training
  data/sample/access_mixed.log    normal + attacks      -> evaluation
  data/sample/access_mixed_labels.csv   line_no,label   (0 = normal, 1 = attack)

Combined Log Format:
  IP - user [time] "METHOD path PROTO" status bytes "referer" "user_agent"

Pure standard library. Seeded for reproducibility.
"""
import argparse
import csv
import os
import random
from datetime import datetime, timedelta, timezone

# ----------------------------------------------------------------------------
# Realistic "normal" traffic vocabulary
# ----------------------------------------------------------------------------
NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/products?page=2",
    "/products?category=books", "/cart", "/checkout", "/login", "/account",
    "/search?q=laptop", "/search?q=headphones", "/api/items", "/api/items?id=42",
    "/static/css/main.css", "/static/js/app.js", "/static/img/logo.png",
    "/favicon.ico", "/blog", "/blog/how-to-cook-rice", "/faq", "/terms",
]
NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36",
]
REFERERS = [
    "-", "https://www.google.com/", "https://example.com/", "https://example.com/products",
    "https://t.co/abc123", "https://www.bing.com/search",
]
METHODS_NORMAL = ["GET", "GET", "GET", "GET", "POST"]  # weighted toward GET

# ----------------------------------------------------------------------------
# Attack traffic vocabulary (labeled = 1)
# ----------------------------------------------------------------------------
SQLI_PATHS = [
    "/products?id=1' OR '1'='1",
    "/products?id=1 UNION SELECT username,password FROM users--",
    "/login?user=admin'--&pass=x",
    "/search?q=1; DROP TABLE users;--",
]
XSS_PATHS = [
    "/search?q=<script>alert(1)</script>",
    "/comment?text=<img src=x onerror=alert(document.cookie)>",
    "/profile?name=<svg/onload=alert(1)>",
]
TRAVERSAL_PATHS = [
    "/../../../../etc/passwd",
    "/static/..%2f..%2f..%2fetc%2fpasswd",
    "/download?file=../../../../windows/win.ini",
]
PROBE_PATHS = [  # sensitive-file / admin probing, usually 403/404
    "/.env", "/.git/config", "/wp-admin/", "/phpmyadmin/", "/admin/config.php",
    "/.aws/credentials", "/backup.sql", "/server-status", "/api/../../etc/shadow",
]
SCANNER_UAS = [
    "sqlmap/1.8#stable (https://sqlmap.org)",
    "Mozilla/5.0 (Nikto/2.5.0)",
    "Nmap Scripting Engine; https://nmap.org/book/nse.html",
    "masscan/1.3",
    "python-requests/2.31.0",
]


def rand_ip(rng, internal=False):
    if internal:
        return f"10.0.{rng.randint(0, 5)}.{rng.randint(1, 254)}"
    return f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def fmt_time(dt):
    # e.g. [22/May/2025:10:55:22 +0000]
    return dt.strftime("[%d/%b/%Y:%H:%M:%S +0000]")


def line(ip, dt, method, path, proto, status, nbytes, referer, ua):
    return f'{ip} - - {fmt_time(dt)} "{method} {path} {proto}" {status} {nbytes} "{referer}" "{ua}"'


def normal_line(rng, dt):
    ip = rand_ip(rng)
    path = rng.choice(NORMAL_PATHS)
    method = rng.choice(METHODS_NORMAL)
    # static assets / found pages mostly 200/304, occasional 404
    if path.startswith("/static") or path == "/favicon.ico":
        status = rng.choice([200, 200, 304])
        nbytes = rng.randint(500, 60000)
    else:
        status = rng.choice([200, 200, 200, 301, 404])
        nbytes = rng.randint(200, 8000) if status < 400 else rng.randint(120, 600)
    return line(ip, dt, method, path, "HTTP/1.1", status, nbytes,
                rng.choice(REFERERS), rng.choice(NORMAL_UAS))


def attack_line(rng, dt):
    kind = rng.choice(["sqli", "xss", "traversal", "probe", "scanner"])
    ua = rng.choice(NORMAL_UAS)
    referer = "-"
    if kind == "sqli":
        path = rng.choice(SQLI_PATHS); method = rng.choice(["GET", "POST"]); status = rng.choice([200, 500, 403])
    elif kind == "xss":
        path = rng.choice(XSS_PATHS); method = "GET"; status = rng.choice([200, 400])
    elif kind == "traversal":
        path = rng.choice(TRAVERSAL_PATHS); method = "GET"; status = rng.choice([403, 404, 200])
    elif kind == "probe":
        path = rng.choice(PROBE_PATHS); method = "GET"; status = rng.choice([403, 404, 401])
        ua = rng.choice(SCANNER_UAS)
    else:  # scanner: hammering many paths with a scanner UA
        path = rng.choice(NORMAL_PATHS + PROBE_PATHS); method = "GET"
        status = rng.choice([200, 404, 403]); ua = rng.choice(SCANNER_UAS)
    nbytes = rng.randint(120, 1500)
    ip = rand_ip(rng)
    return line(ip, dt, method, path, "HTTP/1.1", status, nbytes, referer, ua)


def generate(out_dir, n_normal, n_mixed, attack_ratio, seed):
    rng = random.Random(seed)
    os.makedirs(out_dir, exist_ok=True)
    start = datetime(2026, 6, 1, 8, 0, 0, tzinfo=timezone.utc)

    # 1) pure normal corpus (training)
    t = start
    normal_path = os.path.join(out_dir, "access_normal.log")
    with open(normal_path, "w", encoding="utf-8") as f:
        for _ in range(n_normal):
            t += timedelta(seconds=rng.randint(1, 12))
            f.write(normal_line(rng, t) + "\n")

    # 2) mixed corpus (eval) + label file
    t = start
    mixed_path = os.path.join(out_dir, "access_mixed.log")
    labels_path = os.path.join(out_dir, "access_mixed_labels.csv")
    n_attacks = 0
    with open(mixed_path, "w", encoding="utf-8") as f, \
         open(labels_path, "w", newline="", encoding="utf-8") as lf:
        writer = csv.writer(lf)
        writer.writerow(["line_no", "label"])  # 0 normal, 1 attack
        for i in range(1, n_mixed + 1):
            t += timedelta(seconds=rng.randint(1, 12))
            if rng.random() < attack_ratio:
                f.write(attack_line(rng, t) + "\n"); writer.writerow([i, 1]); n_attacks += 1
            else:
                f.write(normal_line(rng, t) + "\n"); writer.writerow([i, 0])

    return normal_path, mixed_path, labels_path, n_normal, n_mixed, n_attacks


def main():
    ap = argparse.ArgumentParser(description="Generate labeled combined-format access logs.")
    ap.add_argument("--out", default="data/sample", help="output directory")
    ap.add_argument("--normal", type=int, default=8000, help="lines in normal corpus")
    ap.add_argument("--mixed", type=int, default=2000, help="lines in mixed eval corpus")
    ap.add_argument("--attack-ratio", type=float, default=0.15, help="fraction of mixed that are attacks")
    ap.add_argument("--seed", type=int, default=1337)
    a = ap.parse_args()

    np_, mp_, lp_, nn, nm, na = generate(a.out, a.normal, a.mixed, a.attack_ratio, a.seed)
    print(f"wrote {np_}  ({nn} lines, all normal)")
    print(f"wrote {mp_}  ({nm} lines, {na} attacks / {nm - na} normal)")
    print(f"wrote {lp_}  (labels)")


if __name__ == "__main__":
    main()
