#!/usr/bin/env bash
# install.sh — installs Python + curl_cffi. No Node.js needed.
set -euo pipefail

echo "==> detecting OS..."
if [[ -d /data/data/com.termux ]]; then
    OS="termux"
    echo "    Termux detected"
    pkg update -y >/dev/null 2>&1
    pkg install -y python rust clang libffi openssl make pkg-config >/dev/null 2>&1
elif [[ "$(uname)" == "Darwin" ]]; then
    OS="macos"
    brew install python rust pkg-config libffi openssl >/dev/null 2>&1 || true
else
    OS="linux"
    if ! command -v python3 >/dev/null 2>&1; then
        sudo apt-get update -y >/dev/null 2>&1
        sudo apt-get install -y python3 python3-dev python3-pip build-essential libffi-dev libssl-dev pkg-config rustc cargo >/dev/null 2>&1
    fi
fi

# Raise FD limit
ulimit -n 4096 2>/dev/null || true
echo "    FD limit: $(ulimit -n)"

# Install curl_cffi (real Chrome JA3)
echo "==> installing curl_cffi..."
python3 -m pip install --upgrade pip --quiet 2>/dev/null || true
python3 -m pip install curl_cffi --quiet 2>/dev/null || {
    echo "    curl_cffi install failed — trying with --user"
    python3 -m pip install --user curl_cffi --quiet 2>/dev/null || {
        echo "    FAILED — install manually: pip install curl_cffi"
        exit 1
    }
}

# Verify
python3 -c "from curl_cffi.requests import AsyncSession; print('    curl_cffi OK')" 2>/dev/null && {
    echo "==> done."
    echo "    Run: bash run.sh www.moderndoctor.in 10"
} || {
    echo "    curl_cffi verification failed"
    exit 1
}
