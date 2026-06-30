#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$ROOT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required."
  exit 1
fi

VENV_DIR=".venv"
mkdir -p "${VENV_DIR}"
python3 -m venv "${VENV_DIR}"
# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"

python -m pip install --upgrade pip setuptools wheel

if [ -f requirements.txt ]; then
  python -m pip install -r requirements.txt
fi

if [ -f requirements-build.txt ]; then
  python -m pip install -r requirements-build.txt
fi

python -m pip install -e .

cat <<'EOF'
✅ OmniScan environment ready.

Usage:
  source .venv/bin/activate
  omni-vapt scan 127.0.0.1 --html --db --verify
  omni-vapt cve stats
EOF
