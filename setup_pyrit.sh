#!/usr/bin/env bash
# =============================================================================
#  LlamaFirewall / PyRIT PoC — PyRIT Setup (Step 3)
#  Run this on your LAPTOP (Linux). Sets up a Python venv with PyRIT
#  and all dependencies needed for the red-team scenarios.
#
#  Usage:
#    chmod +x setup_pyrit.sh && ./setup_pyrit.sh
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${CYAN}==> $*${NC}"; }
ok()  { echo -e "${GREEN} ✓  $*${NC}"; }

VENV_DIR="./venv"

log "Checking Python version..."
PYTHON=$(command -v python3)
PY_VERSION=$($PYTHON --version 2>&1)
echo "  Found: ${PY_VERSION}"

log "Creating virtual environment at ${VENV_DIR}..."
# Auto-install python3-venv for the current Python version
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
sudo apt-get install -y -qq "python3.${PY_VER}-venv" 2>/dev/null || true
$PYTHON -m venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"

log "Upgrading pip..."
pip install --upgrade pip --quiet

log "Installing PyRIT and dependencies..."
# pyrit — Microsoft's AI red-teaming toolkit
# openai  — PyRIT's OpenAI target uses this client
# pandas, tabulate — result formatting
pip install \
  pyrit \
  openai \
  pandas \
  tabulate \
  python-dotenv \
  --quiet

ok "All packages installed."

log "Verifying PyRIT import..."
python3 -c "import pyrit; print(f'  PyRIT version: {pyrit.__version__}')"

cat << EOF

${GREEN}============================================================
  PyRIT environment ready.
============================================================${NC}

  Activate with:  source ${VENV_DIR}/bin/activate
  Run attacks:    python3 pyrit_redteam.py

  Make sure the SSH tunnel is open before running:
    ssh -N -L 8080:localhost:8080 azureuser@<vm-fqdn>
  Or just use: ./test_tunnel.sh azureuser@<vm-fqdn>

EOF
