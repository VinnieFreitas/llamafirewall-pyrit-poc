#!/usr/bin/env bash
# =============================================================================
#  LlamaFirewall / PyRIT PoC — VM Setup Script (Step 2)
#  Run this ON the Azure VM after deployment.
#
#  What this script does:
#    1. System update + dependencies (with apt-lock handling)
#    2. Ollama install + Phi-3-mini pull (smoke-tested via REST, not CLI)
#    3. Python venv + LlamaFirewall + FastAPI
#    4. HfFolder compatibility patch (huggingface_hub >= 0.25 fix)
#    5. Deploy proxy.py
#    6. HuggingFace login + PromptGuard 2 model pre-download
#    7. Systemd service with HF_TOKEN injected
#    8. Health checks
#
#  Usage (from your laptop):
#    scp setup_vm.sh proxy.py azureuser@<vm-fqdn>:~/
#    ssh azureuser@<vm-fqdn> 'bash ~/setup_vm.sh 2>&1 | tee ~/setup.log'
#
#  Prerequisites:
#    - HuggingFace account + access to meta-llama/Llama-Prompt-Guard-2-86M
#    - HuggingFace read token from https://huggingface.co/settings/tokens
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[$(date +%H:%M:%S)] ==> $*${NC}"; }
ok()   { echo -e "${GREEN}[$(date +%H:%M:%S)]  ✓  $*${NC}"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)]  ⚠  $*${NC}"; }
fail() { echo -e "${RED}[$(date +%H:%M:%S)]  ✗  $*${NC}"; exit 1; }

INSTALL_DIR="/opt/llamafirewall"
SERVICE_USER="azureuser"
OLLAMA_MODEL="phi3:mini"
FIREWALL_PORT=8080
OLLAMA_PORT=11434

# =============================================================================
#  PREFLIGHT — wait for any background apt to finish
#  Azure VMs run unattended-upgrades on first boot. If we don't wait, apt
#  will fail with a lock error. 2-minute grace period, then force-clear.
# =============================================================================
log "Waiting for apt lock..."
LOCK_WAIT=0
while sudo fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
    sleep 3; LOCK_WAIT=$((LOCK_WAIT + 3))
    [[ $LOCK_WAIT -gt 120 ]] && {
        warn "apt lock held >2 min — clearing"
        sudo killall apt apt-get 2>/dev/null || true
        sudo rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock \
                   /var/lib/dpkg/lock-frontend
        sudo dpkg --configure -a
        break
    }
done

# =============================================================================
#  1. SYSTEM PACKAGES
# =============================================================================
log "Updating system packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

log "Installing dependencies..."
sudo apt-get install -y -qq \
    python3 python3-pip python3-venv python3-dev \
    git curl wget build-essential jq net-tools
ok "System packages ready."

# =============================================================================
#  2. OLLAMA
# =============================================================================
log "Installing Ollama..."
if command -v ollama &>/dev/null; then
    warn "Ollama already installed — skipping."
else
    curl -fsSL https://ollama.com/install.sh | sudo bash
    ok "Ollama installed."
fi

sudo systemctl enable ollama --quiet
sudo systemctl start  ollama

log "Waiting for Ollama API..."
RETRIES=20
until curl -sf http://localhost:${OLLAMA_PORT}/api/tags >/dev/null 2>&1; do
    RETRIES=$((RETRIES-1)); [[ $RETRIES -le 0 ]] && fail "Ollama API timeout."; sleep 3
done
ok "Ollama up at localhost:${OLLAMA_PORT}."

log "Pulling ${OLLAMA_MODEL} (~2.3 GB)..."
ollama pull "${OLLAMA_MODEL}"
ok "Model ${OLLAMA_MODEL} ready."

# Smoke-test via REST API — avoids the interactive-mode hang of 'ollama run'
log "Smoke-testing Ollama REST API..."
SMOKE=$(curl -sf --max-time 60 \
    http://localhost:${OLLAMA_PORT}/api/generate \
    -d "{\"model\":\"${OLLAMA_MODEL}\",\"prompt\":\"Reply with the single word OK.\",\"stream\":false}" \
    2>/dev/null || true)
if echo "${SMOKE}" | grep -qi "ok"; then
    ok "Ollama smoke-test passed."
else
    warn "Smoke-test inconclusive — continuing (model may still be warming up)."
fi

# =============================================================================
#  3. PYTHON VENV + PACKAGES
# =============================================================================
log "Creating Python venv at ${INSTALL_DIR}..."
sudo mkdir -p "${INSTALL_DIR}"
sudo chown "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"
python3 -m venv "${INSTALL_DIR}/venv"
source "${INSTALL_DIR}/venv/bin/activate"
pip install --upgrade pip --quiet

log "Installing LlamaFirewall and dependencies (~2 GB for torch)..."
pip install llamafirewall transformers torch fastapi uvicorn httpx --quiet
ok "Python packages installed."

# =============================================================================
#  4. HFFOLDER COMPATIBILITY PATCH
#
#  huggingface_hub >= 0.25 removed HfFolder. LlamaFirewall's promptguard_utils
#  still imports it. Downgrading conflicts with transformers, so we shim it.
# =============================================================================
log "Patching LlamaFirewall for huggingface_hub >= 0.25 compatibility..."

PG_UTILS="${INSTALL_DIR}/venv/lib/python3.10/site-packages/llamafirewall/scanners/promptguard_utils.py"
[[ ! -f "${PG_UTILS}" ]] && fail "promptguard_utils.py not found — check LlamaFirewall install."

python3 - << PYEOF
path = "${PG_UTILS}"
content = open(path).read()
old = "from huggingface_hub import HfFolder, login"
new = """from huggingface_hub import login
try:
    from huggingface_hub import HfFolder
except ImportError:
    import huggingface_hub as _hf
    class HfFolder:
        @staticmethod
        def get_token():
            return _hf.get_token()
        @staticmethod
        def save_token(token: str) -> None:
            pass"""
if old in content:
    open(path, "w").write(content.replace(old, new))
    print("  Patch applied successfully.")
elif "class HfFolder" in content:
    print("  Patch already present — skipping.")
else:
    print("  WARNING: target string not found. LlamaFirewall version may have changed.")
PYEOF

# Verify full import chain
python3 -c "
from llamafirewall import LlamaFirewall, ScannerType, Role, UserMessage, ScanDecision
print('  Import chain OK')
" || fail "Import verification failed after patch."
ok "Compatibility patch applied."

# =============================================================================
#  5. DEPLOY PROXY.PY
# =============================================================================
log "Deploying proxy.py..."
if [[ -f "/home/${SERVICE_USER}/proxy.py" ]]; then
    cp "/home/${SERVICE_USER}/proxy.py" "${INSTALL_DIR}/proxy.py"
    ok "proxy.py deployed to ${INSTALL_DIR}."
else
    fail "proxy.py not found in ~. Run: scp proxy.py azureuser@<vm-fqdn>:~/"
fi

# =============================================================================
#  6. HUGGINGFACE LOGIN + PROMPTGUARD 2 PRE-DOWNLOAD
#
#  Llama-Prompt-Guard-2-86M is gated by Meta on HuggingFace.
#  You must have accepted the license at:
#  https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M
# =============================================================================
log "HuggingFace login (needed for PromptGuard 2 model download)..."
echo ""
echo "  ► Accept the model license first (if you haven't):"
echo "    https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M"
echo "  ► Get your token:"
echo "    https://huggingface.co/settings/tokens"
echo ""
hf auth login

HF_TOKEN=$(cat ~/.cache/huggingface/token 2>/dev/null || true)
[[ -z "${HF_TOKEN}" ]] && fail "Could not read HuggingFace token after login."

log "Pre-downloading PromptGuard 2 model (~170 MB)..."
HF_HOME="${INSTALL_DIR}/.cache/huggingface" \
HUGGING_FACE_HUB_TOKEN="${HF_TOKEN}" \
python3 -c "
import os
from transformers import AutoTokenizer, AutoModelForSequenceClassification
model_id = 'meta-llama/Llama-Prompt-Guard-2-86M'
token = os.environ['HUGGING_FACE_HUB_TOKEN']
print('  Downloading tokenizer...')
AutoTokenizer.from_pretrained(model_id, token=token)
print('  Downloading model weights...')
AutoModelForSequenceClassification.from_pretrained(model_id, token=token)
print('  Done.')
"
ok "PromptGuard 2 cached at ${INSTALL_DIR}/.cache/huggingface"

# =============================================================================
#  7. SYSTEMD SERVICE
# =============================================================================
log "Creating llamafirewall.service..."

sudo tee /etc/systemd/system/llamafirewall.service > /dev/null << SERVICE_EOF
[Unit]
Description=LlamaFirewall Proxy (OpenAI-compatible, port ${FIREWALL_PORT})
After=network.target ollama.service
Requires=ollama.service

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=${INSTALL_DIR}/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
Environment="PYTHONUNBUFFERED=1"
Environment="HF_HOME=${INSTALL_DIR}/.cache/huggingface"
Environment="HUGGING_FACE_HUB_TOKEN=${HF_TOKEN}"

ExecStart=${INSTALL_DIR}/venv/bin/uvicorn proxy:app \
    --host 127.0.0.1 \
    --port ${FIREWALL_PORT} \
    --workers 1 \
    --log-level warning

Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=llamafirewall

[Install]
WantedBy=multi-user.target
SERVICE_EOF

sudo systemctl daemon-reload
sudo systemctl enable llamafirewall --quiet
sudo systemctl start  llamafirewall
ok "llamafirewall.service started."

# =============================================================================
#  8. HEALTH CHECKS
# =============================================================================
log "Health check — Ollama..."
curl -sf http://localhost:${OLLAMA_PORT}/api/tags >/dev/null \
    && ok "Ollama  → localhost:${OLLAMA_PORT} — UP" \
    || fail "Ollama health check failed."

log "Health check — LlamaFirewall (waits for PromptGuard weights to load)..."
RETRIES=40
until curl -sf http://localhost:${FIREWALL_PORT}/health >/dev/null 2>&1; do
    RETRIES=$((RETRIES-1))
    [[ $RETRIES -le 0 ]] && {
        warn "Check logs: journalctl -u llamafirewall -f"
        fail "LlamaFirewall health check timeout."
    }
    sleep 5
done
ok "LlamaFirewall → localhost:${FIREWALL_PORT} — UP"

log "End-to-end test..."
E2E=$(curl -sf --max-time 120 \
    -X POST http://localhost:${FIREWALL_PORT}/v1/chat/completions \
    -H "Content-Type: application/json" \
    -d '{"model":"phi3:mini","messages":[{"role":"user","content":"What is 2 + 2?"}]}' \
    2>/dev/null || true)

if echo "${E2E}" | jq -e '.choices[0].message.content' >/dev/null 2>&1; then
    REPLY=$(echo "${E2E}" | jq -r '.choices[0].message.content')
    ok "End-to-end passed. Reply: \"${REPLY:0:60}\""
else
    warn "End-to-end inconclusive — service running, model may still be loading."
fi

echo -e "${GREEN}
============================================================
  Setup complete!
============================================================${NC}
  ollama.service        → localhost:${OLLAMA_PORT}
  llamafirewall.service → localhost:${FIREWALL_PORT}

  Useful commands:
    journalctl -u llamafirewall -f -o cat   # live security logs
    sudo systemctl status llamafirewall     # service status

  From your laptop:
    ssh -N -L 8080:localhost:8080 ${SERVICE_USER}@<vm-fqdn>
"
