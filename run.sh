#!/usr/bin/env bash
# run.sh — one command. Python + curl_cffi. No Node.js.
# Usage: bash run.sh www.moderndoctor.in 10 [--proxy]
set -euo pipefail
cd "$(dirname "$0")"

TARGET="${1:?usage: bash run.sh <target> <minutes> [--proxy]}"
MINUTES="${2:-10}"
PROXY_FLAG=""
[[ "${3:-}" == "--proxy" ]] && PROXY_FLAG="--proxy"

# Auto-install if curl_cffi missing
if ! python3 -c "from curl_cffi.requests import AsyncSession" 2>/dev/null; then
    bash install.sh
fi

# Run master orchestrator
exec python3 master.py "$TARGET" "$MINUTES" $PROXY_FLAG
