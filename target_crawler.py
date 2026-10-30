#!/usr/bin/env python3
"""target_crawler.py — Deep target reconnaissance.

Fix: Bug 2 — Next.js App Router HEAD doesn't return correct Content-Length.
     Now uses GET + reads actual stream bytes for accurate size measurement.
Fix: 308 redirect traps — follows redirects, records final working URL.
Added: sitemap.xml parsing, robots.txt parsing, source map discovery.

Usage:
  python3 target_crawler.py www.moderndoctor.in
"""

import http.client
import json
import re
import ssl
import sys
import time
import xml.etree.ElementTree as ET

_ctx = ssl._create_unverified_context()
TARGET = sys.argv[1] if len(sys.argv) > 1 else "www.moderndoctor.in"
_h = TARGET.replace("https://", "").replace("http://", "").rstrip("/")
_h = _h[4:] if _h.startswith("www.") else _h
HOST = f"www.{_h}"

# Known Next.js page paths (test BOTH with and without trailing slash)
SEED_PATHS = [
    "blog", "doctor", "conditions/acne", "conditions/stress",
    "conditions/allergies", "conditions/alopecia", "conditions/anxiety",
    "conditions/arthritis", "conditions/behavioral-support", "conditions/dandruff",
    "conditions/eczema", "conditions/hair-fall", "conditions/immunity",
    "conditions/low-immunity", "conditions/migraine", "conditions/sinus",
    "conditions/sleep-disturbance", "conditions/thyroid", "case-studies",
]

# ─── HTTP helpers ────────────────────────────────────────────────────────

def _request(path, method="GET", follow_redirect=True, depth=0):
    """HTTP request with actual byte measurement.
    Returns (status, body_bytes, latency_ms, final_path, headers).
    Follows 308/301 redirects up to 3 times."""
    if depth > 3:
        return 0, b"", 0, path, {}
    try:
        conn = http.client.HTTPSConnection(HOST, timeout=10, context=_ctx)
        t0 = time.perf_counter()
        conn.request(method, path, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Encoding": "identity",  # No gzip — measure real size
            "Connection": "close",
        })
        resp = conn.getresponse()
        body = resp.read()  # ACTUAL STREAM BYTES — not Content-Length header
        latency = (time.perf_counter() - t0) * 1000
        status = resp.status
        headers = dict(resp.getheaders())
        conn.close()

        # Follow redirects (308, 301, 302, 307)
        if follow_redirect and status in (301, 302, 307, 308):
            location = headers.get("Location") or headers.get("location") or ""
            if location:
                # Resolve relative URLs
                if location.startswith("/"):
                    final_path = location
                elif location.startswith(f"https://{HOST}"):
                    final_path = location[len(f"https://{HOST}"):]
                elif location.startswith(f"http://{HOST}"):
                    final_path = location[len(f"http://{HOST}"):]
                else:
                    final_path = path  # External redirect, don't follow
                    return status, body, latency, final_path, headers

                if final_path != path:
                    return _request(final_path, method, follow_redirect, depth + 1)

        return status, body, latency, path, headers
    except Exception as e:
        return 0, b"", 0, path, {"error": str(e)[:60]}

def _get_size(path):
    """GET request, measure actual body bytes. Returns (status, size, final_path).
    This is the FIX for Bug 2 — HEAD doesn't give correct Content-Length on Next.js."""
    status, body, latency, final_path, headers = _request(path, method="GET")
    return status, len(body), final_path

# ─── Sitemap parsing ─────────────────────────────────────────────────────

def _parse_sitemap():
    """Fetch and parse sitemap.xml for all URLs."""
    urls = []
    status, body, _, _, _ = _request("/sitemap.xml", follow_redirect=True)
    if status == 200 and body:
        try:
            root = ET.fromstring(body)
            # Standard sitemap namespace
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for url_elem in root.findall(".//sm:url/sm:loc", ns):
                if url_elem.text:
                    loc = url_elem.text.strip()
                    # Extract path from full URL
                    if HOST in loc:
                        path = loc.split(HOST, 1)[1]
                    elif loc.startswith("https://"):
                        continue  # External URL
                    else:
                        path = loc
                    if path and path.startswith("/"):
                        urls.append(path)
            # Also check for sub-sitemaps
            for sitemap_elem in root.findall(".//sm:sitemap/sm:loc", ns):
                if sitemap_elem.text:
                    sub_url = sitemap_elem.text.strip()
                    if HOST in sub_url:
                        sub_path = sub_url.split(HOST, 1)[1]
                        sub_status, sub_body, _, _, _ = _request(sub_path, follow_redirect=True)
                        if sub_status == 200 and sub_body:
                            sub_root = ET.fromstring(sub_body)
                            for url_elem in sub_root.findall(".//sm:url/sm:loc", ns):
                                if url_elem.text:
                                    loc = url_elem.text.strip()
                                    if HOST in loc:
                                        path = loc.split(HOST, 1)[1]
                                        if path and path.startswith("/"):
                                            urls.append(path)
        except ET.ParseError:
            pass
    return urls

# ─── Robots.txt parsing ──────────────────────────────────────────────────

def _parse_robots():
    """Fetch robots.txt, extract Disallow paths (these are intel — paths exist)."""
    paths = []
    status, body, _, _, _ = _request("/robots.txt", follow_redirect=True)
    if status == 200 and body:
        for line in body.decode("utf-8", errors="replace").split("\n"):
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/" and path.startswith("/"):
                    paths.append(path)
    return paths

# ─── Asset extraction ────────────────────────────────────────────────────

def _extract_assets(html_text):
    """Extract all asset URLs from HTML. Returns set of paths."""
    assets = set()
    # Script src (JS bundles = biggest)
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html_text, re.I):
        url = m.group(1)
        if url.startswith("/"):
            assets.add(url)
        elif url.startswith("https://") and HOST in url:
            assets.add(url.split(HOST, 1)[1])
    # Stylesheet links
    for m in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\'][^>]*stylesheet', html_text, re.I):
        url = m.group(1)
        if url.startswith("/"):
            assets.add(url)
        elif url.startswith("https://") and HOST in url:
            assets.add(url.split(HOST, 1)[1])
    # Preload/prefetch links
    for m in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\'][^>]*(?:preload|prefetch)', html_text, re.I):
        url = m.group(1)
        if url.startswith("/"):
            assets.add(url)
    # Font files
    for m in re.finditer(r'<link[^>]+href=["\']([^"\']+\.woff2?)["\']', html_text, re.I):
        url = m.group(1)
        if url.startswith("/"):
            assets.add(url)
    return assets

def _check_sourcemap(js_path):
    """Check if .map file exists for a JS bundle. Returns (path, size) or None."""
    map_path = js_path + ".map"
    status, size, final = _get_size(map_path)
    if status == 200 and size > 1000:
        return map_path, size
    return None

# ─── Main ───────────────────────────────────────────────────────────────

def main():
    print(f"{'='*60}", flush=True)
    print(f"TARGET CRAWLER: {HOST}", flush=True)
    print(f"{'='*60}\n", flush=True)

    targets = []

    # ─── Phase 1: Homepage ─────────────────────────────────────────────
    print("[1/6] Homepage...", flush=True)
    status, body, latency, final, headers = _request("/", method="GET")
    if status != 200 or not body:
        print(f"  FAIL: homepage {status}", flush=True)
        return
    homepage_size = len(body)
    print(f"  {status} {homepage_size/1024:.0f}KB {latency:.0f}ms final:{final}", flush=True)
    targets.append({"path": final, "size": homepage_size, "type": "page"})

    # ─── Phase 2: Extract assets from homepage HTML ────────────────────
    print("[2/6] Extracting assets from HTML...", flush=True)
    html_text = body.decode("utf-8", errors="replace")
    assets = _extract_assets(html_text)
    print(f"  Found {len(assets)} asset URLs", flush=True)

    # ─── Phase 3: Measure asset sizes (GET, not HEAD) ──────────────────
    print("[3/6] Measuring asset sizes (GET + actual bytes)...", flush=True)
    for url in sorted(assets):
        s, sz, final_url = _get_size(url)
        if s == 200 and sz > 0:
            targets.append({"path": final_url, "size": sz, "type": "asset"})
            tag = " ← BIG" if sz > 100000 else " ← HUGE!" if sz > 500000 else ""
            print(f"    {s} {sz/1024:.0f}KB {final_url[:65]}{tag}", flush=True)
        elif s == 304:
            # 304 = cached, need to estimate size from first response
            targets.append({"path": url, "size": 50000, "type": "asset"})  # estimate
            print(f"    {s} ~50KB (cached) {url[:65]}", flush=True)

    # ─── Phase 4: Check source maps ────────────────────────────────────
    print("[4/6] Checking source maps...", flush=True)
    sm_count = 0
    for t in list(targets):
        if t["type"] == "asset" and t["path"].endswith(".js") and t["size"] > 10000:
            sm = _check_sourcemap(t["path"])
            if sm:
                targets.append({"path": sm[0], "size": sm[1], "type": "sourcemap"})
                print(f"    SOURCEMAP {sm[1]/1024:.0f}KB {sm[0][:65]} ← JACKPOT!", flush=True)
                sm_count += 1
    if sm_count == 0:
        print(f"    No source maps found (production build)", flush=True)

    # ─── Phase 5: Test page paths (avoid 308 traps) ────────────────────
    print("[5/6] Testing page paths (308 avoidance)...", flush=True)
    for seed in SEED_PATHS:
        # Test WITHOUT trailing slash
        s1, sz1, f1 = _get_size(f"/{seed}")
        if s1 == 200 and sz1 > 5000:
            targets.append({"path": f1, "size": sz1, "type": "page"})
            print(f"    {s1} {sz1/1024:.0f}KB /{seed}", flush=True)
            continue
        # Test WITH trailing slash
        s2, sz2, f2 = _get_size(f"/{seed}/")
        if s2 == 200 and sz2 > 5000:
            targets.append({"path": f2, "size": sz2, "type": "page"})
            print(f"    {s2} {sz2/1024:.0f}KB /{seed}/ (slash)", flush=True)
            continue
        # If both redirect, follow the redirect
        if s1 in (301, 308) or s2 in (301, 308):
            # _request already follows redirects — if we're here, both failed
            pass

    # ─── Phase 6: Sitemap + robots.txt ─────────────────────────────────
    print("[6/6] Sitemap + robots.txt...", flush=True)
    sitemap_urls = _parse_sitemap()
    print(f"  Sitemap: {len(sitemap_urls)} URLs found", flush=True)
    # Test top 10 sitemap URLs for size
    for url in sitemap_urls[:10]:
        s, sz, f = _get_size(url)
        if s == 200 and sz > 5000:
            targets.append({"path": f, "size": sz, "type": "page"})
            print(f"    {s} {sz/1024:.0f}KB {f[:65]}", flush=True)

    robots_paths = _parse_robots()
    print(f"  Robots.txt: {len(robots_paths)} Disallow paths", flush=True)

    # ─── Sort by size (biggest first = max bandwidth per request) ──────
    targets.sort(key=lambda x: x["size"], reverse=True)

    # Remove duplicates (same path)
    seen = set()
    unique = []
    for t in targets:
        if t["path"] not in seen:
            seen.add(t["path"])
            unique.append(t)
    targets = unique

    # Write targets.json
    with open("targets.json", "w") as f:
        json.dump(targets, f, indent=2)

    # Report
    print(f"\n{'='*60}", flush=True)
    print(f"CRAWLER COMPLETE", flush=True)
    print(f"{'='*60}", flush=True)
    print(f"  Total targets: {len(targets)}", flush=True)
    print(f"  Top 10 (biggest):", flush=True)
    for t in targets[:10]:
        print(f"    {t['size']/1024:.0f}KB  {t['type']:10s}  {t['path'][:50]}", flush=True)
    avg_top5 = sum(t["size"] for t in targets[:5]) / min(len(targets), 5)
    avg_top10 = sum(t["size"] for t in targets[:10]) / min(len(targets), 10)
    print(f"\n  Top 5 avg: {avg_top5/1024:.0f}KB per request", flush=True)
    print(f"  Top 10 avg: {avg_top10/1024:.0f}KB per request", flush=True)
    print(f"  Expected burn: 2388 req/s × {avg_top5/1024:.0f}KB = {2388*avg_top5/1048576:.0f}MB/s", flush=True)
    print(f"  ETA to 100GB: ~{102400/(2388*avg_top5/1048576)/60:.0f} min (Codespaces)", flush=True)
    print(f"  ETA to 100GB: ~{102400/(200*avg_top5/1048576)/3600:.1f} hours (Termux)", flush=True)
    print(f"{'='*60}", flush=True)

if __name__ == "__main__":
    main()
