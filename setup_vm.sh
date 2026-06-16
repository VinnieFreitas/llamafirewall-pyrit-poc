#!/usr/bin/env bash
# =============================================================================
#  LlamaFirewall / PyRIT — VM Setup Script (Step 2)
#  Run this ON the Azure VM after deployment.
#
#  Usage (from your laptop):
#    scp setup_vm.sh proxy.py social_engineering_pt.nov azureuser@<vm-fqdn>:~/
#    ssh azureuser@<vm-fqdn> 'bash ~/setup_vm.sh [--profile lab|preprod|production] 2>&1 | tee ~/setup.log'
#
#  If --profile is omitted the script prompts interactively.
#
#  Profiles:
#    lab        — phi3:mini    · threshold 0.05 · no output scan  · ~20 min
#    preprod    — mistral:7b   · threshold 0.10 · output scan on  · ~35 min
#    production — llama3:8b   · threshold 0.15 · output scan on  · ~45 min
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
FIREWALL_PORT=8080
OLLAMA_PORT=11434

# Initialised here — overwritten after HuggingFace login in section 6
HF_TOKEN=""

# =============================================================================
#  PROFILE SELECTION
# =============================================================================

PROFILE="${1:-}"
[[ "${PROFILE}" == "--profile" ]] && PROFILE="${2:-}"
[[ "${PROFILE}" == --profile=* ]] && PROFILE="${PROFILE#--profile=}"

# --corp flag — forces proxy to bind on 0.0.0.0 (corp-lab LlamaFirewall VM)
# Use when running --profile lab on a VM that needs to be reached from another VM
CORP_DEPLOY="0"
for arg in "$@"; do
    [[ "${arg}" == "--corp" ]] && CORP_DEPLOY="1"
done

if [[ -z "${PROFILE}" ]]; then
    echo ""
    echo -e "${CYAN}============================================================"
    echo "  Select environment profile:"
    echo -e "============================================================${NC}"
    echo ""
    echo "  1) lab        — phi3:mini  · threshold 0.05 · no output scan"
    echo "  2) preprod    — mistral:7b · threshold 0.10 · output scan on"
    echo "  3) production — llama3:8b  · threshold 0.15 · output scan on"
    echo ""
    read -rp "Enter profile [1/2/3] (default: 1): " PROFILE_CHOICE
    case "${PROFILE_CHOICE}" in
        2) PROFILE="preprod"    ;;
        3) PROFILE="production" ;;
        *) PROFILE="lab"        ;;
    esac
fi

case "${PROFILE}" in
    lab)
        OLLAMA_MODEL="phi3:mini"
        PG_THRESHOLD="0.05"
        OUTPUT_SCAN="0"
        NOVA_LLM="0"
        LLAMA_GUARD_DISABLED="0"
        PROFILE_LF_INGESTION="shared_key"
        ;;
    preprod)
        OLLAMA_MODEL="mistral:7b"
        PG_THRESHOLD="0.10"
        OUTPUT_SCAN="1"
        NOVA_LLM="0"
        LLAMA_GUARD_DISABLED="0"
        PROFILE_LF_INGESTION="managed_identity"
        ;;
    production)
        OLLAMA_MODEL="llama3:8b"
        PG_THRESHOLD="0.15"
        OUTPUT_SCAN="1"
        NOVA_LLM="1"
        LLAMA_GUARD_DISABLED="0"
        PROFILE_LF_INGESTION="managed_identity"
        ;;
    *)
        fail "Unknown profile '${PROFILE}'. Use: lab | preprod | production"
        ;;
esac

echo ""
log "Profile: ${PROFILE}"
echo "  LLM model        : ${OLLAMA_MODEL}"
echo "  PG threshold     : ${PG_THRESHOLD}"
echo "  Output scanning  : ${OUTPUT_SCAN}"
echo "  NOVA LLM tier    : ${NOVA_LLM}"
echo ""

# =============================================================================
#  PREFLIGHT — wait for any background apt processes to finish
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

log "Pulling model: ${OLLAMA_MODEL}..."
ollama pull "${OLLAMA_MODEL}"
ok "Model ${OLLAMA_MODEL} ready."

# Smoke-test via REST API (avoids the interactive-mode hang of 'ollama run')
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
#  3. PULL LLAMA GUARD 3:8B
# =============================================================================
log "Pulling LlamaGuard 3:8B (~4.7 GB)..."
ollama pull llama-guard3:8b
ok "llama-guard3:8b ready."

# =============================================================================
#  4. PYTHON VENV + PACKAGES
# =============================================================================
log "Creating Python venv at ${INSTALL_DIR}..."
sudo mkdir -p "${INSTALL_DIR}"
sudo chown "${SERVICE_USER}" "${INSTALL_DIR}"

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
sudo apt-get install -y -qq "python3.${PY_VER}-venv" 2>/dev/null || true

python3 -m venv "${INSTALL_DIR}/venv"
source "${INSTALL_DIR}/venv/bin/activate"
pip install --upgrade pip --quiet

log "Installing LlamaFirewall and dependencies (~2 GB for torch)..."
pip install llamafirewall transformers torch fastapi uvicorn httpx --quiet
ok "Python packages installed."

log "Installing NOVA prompt pattern matching engine..."
pip install nova-hunting --quiet
ok "nova-hunting installed."

# =============================================================================
#  5. HFFOLDER COMPATIBILITY PATCH
# =============================================================================
log "Patching LlamaFirewall for huggingface_hub >= 0.25 compatibility..."

PG_UTILS="${INSTALL_DIR}/venv/lib/python3.10/site-packages/llamafirewall/scanners/promptguard_utils.py"
[[ ! -f "${PG_UTILS}" ]] && fail "promptguard_utils.py not found."

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
    print("  Patch applied.")
elif "class HfFolder" in content:
    print("  Patch already applied — skipping.")
else:
    print("  WARNING: Target string not found.")
PYEOF

python3 -c "
from llamafirewall import LlamaFirewall, ScannerType, Role, UserMessage, ScanDecision
print('  LlamaFirewall import chain: OK')
" || fail "Import check failed."
ok "Compatibility patch applied."

# =============================================================================
#  6. DEPLOY PROXY.PY
# =============================================================================
log "Deploying proxy.py..."
# Handle both deployment methods:
#   1. scp proxy.py azureuser@<vm>:~/          (home-lab, files copied directly)
#   2. git clone <repo> ~/llamafirewall-pyrit-poc  (corp-lab, cloned from git)
PROXY_SRC=""
if [[ -f "/home/${SERVICE_USER}/proxy.py" ]]; then
    PROXY_SRC="/home/${SERVICE_USER}/proxy.py"
elif [[ -f "/home/${SERVICE_USER}/llamafirewall-pyrit-poc/proxy.py" ]]; then
    PROXY_SRC="/home/${SERVICE_USER}/llamafirewall-pyrit-poc/proxy.py"
fi

if [[ -n "${PROXY_SRC}" ]]; then
    cp "${PROXY_SRC}" "${INSTALL_DIR}/proxy.py"
    ok "proxy.py deployed from ${PROXY_SRC}."
else
    fail "proxy.py not found. Either:\n  scp proxy.py azureuser@<vm-fqdn>:~/\n  or clone the repo: git clone <repo-url> ~/llamafirewall-pyrit-poc"
fi

# =============================================================================
#  7. NOVA RULES
# =============================================================================
log "Setting up NOVA rules..."

log "Cloning NOVA official rules..."
git clone https://github.com/Nova-Hunting/nova-rules \
    "${INSTALL_DIR}/nova-rules" 2>/dev/null \
    || git -C "${INSTALL_DIR}/nova-rules" pull
ok "Official NOVA rules cloned."

mkdir -p "${INSTALL_DIR}/nova-rules-custom"

NOV_SRC=""
if [[ -f "/home/${SERVICE_USER}/social_engineering_pt.nov" ]]; then
    NOV_SRC="/home/${SERVICE_USER}/social_engineering_pt.nov"
elif [[ -f "/home/${SERVICE_USER}/llamafirewall-pyrit-poc/social_engineering_pt.nov" ]]; then
    NOV_SRC="/home/${SERVICE_USER}/llamafirewall-pyrit-poc/social_engineering_pt.nov"
fi

if [[ -n "${NOV_SRC}" ]]; then
    cp "${NOV_SRC}" "${INSTALL_DIR}/nova-rules-custom/"
    ok "Custom NOVA rules deployed from ${NOV_SRC}."
else
    warn "social_engineering_pt.nov not found — deploy manually:"
    echo "  scp social_engineering_pt.nov ${SERVICE_USER}@<vm-fqdn>:/opt/llamafirewall/nova-rules-custom/"
fi

# =============================================================================
#  8. HUGGINGFACE LOGIN + PROMPTGUARD 2 PRE-DOWNLOAD
# =============================================================================
log "HuggingFace login required for PromptGuard 2 model download."
echo ""
echo "  ► Accept the model licence first (if you haven't):"
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
#  9. SYSTEMD SERVICE
#  Always rewrite the service file — even on re-runs — so profile changes
#  (bind address, thresholds, output scan) take effect immediately.
# =============================================================================

# Bind address:
#   home-lab (laptop PyRIT): 127.0.0.1 — SSH tunnel handles routing
#   corp profiles (PyRIT VM on same VNet): 0.0.0.0 — direct VNet access
#
# The --corp flag forces 0.0.0.0 regardless of profile.
# Use this when running --profile lab on a corp-lab LlamaFirewall VM:
#   bash setup_vm.sh --profile lab --corp
#
BIND_HOST="127.0.0.1"
if [[ "${PROFILE}" != "lab" ]] || [[ "${CORP_DEPLOY:-0}" == "1" ]]; then
    BIND_HOST="0.0.0.0"
fi

log "Creating llamafirewall.service (profile: ${PROFILE}, bind: ${BIND_HOST})..."

# Stop any running instance before rewriting the service file
sudo systemctl stop llamafirewall 2>/dev/null || true

sudo tee /etc/systemd/system/llamafirewall.service > /dev/null << SERVICE_EOF
[Unit]
Description=LlamaFirewall Proxy [${PROFILE}] port ${FIREWALL_PORT} bind ${BIND_HOST}
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
Environment="LLAMAFIREWALL_PROFILE=${PROFILE}"
Environment="PROMPTGUARD_THRESHOLD=${PG_THRESHOLD}"
Environment="OUTPUT_SCAN_ENABLED=${OUTPUT_SCAN}"
Environment="NOVA_LLM_ENABLED=${NOVA_LLM}"
Environment="LLAMA_GUARD_DISABLED=${LLAMA_GUARD_DISABLED}"

# Perplexity filter — adversarial suffix detection via GPT-2
# Disabled by default — requires ~500 MB GPT-2 model download on first run
Environment="PERPLEXITY_FILTER_ENABLED=0"
Environment="PERPLEXITY_THRESHOLD=500.0"

# Crescendo session tracker — multi-turn escalation detection
Environment="CRESCENDO_ENABLED=1"
Environment="CRESCENDO_NEAR_MISS_THRESHOLD=0.03"
Environment="CRESCENDO_BLOCK_AFTER=3"
Environment="CRESCENDO_SESSION_TTL=3600"

# ---------------------------------------------------------------------------
#  Prompt logging — ships full prompt to LlamaFirewallPrompts_CL in LAW.
#  Disabled by default. Enable after configuring table-level RBAC in LAW.
#  Set LAW_WORKSPACE_ID and LAW_WORKSPACE_KEY to your Sentinel workspace.
#  See README: "Prompt Logging to Sentinel" for full setup instructions.
# ---------------------------------------------------------------------------
Environment="PROMPT_LOGGING_ENABLED=0"
Environment="LAW_WORKSPACE_ID="
Environment="LAW_WORKSPACE_KEY="
Environment="PII_REDACTION_ENABLED=0"
Environment="AZURE_LANGUAGE_ENDPOINT="
Environment="AZURE_LANGUAGE_KEY="

# ---------------------------------------------------------------------------
#  LAW ingestion method — set automatically based on profile
#  lab/corp-lab:      shared_key (HMAC-SHA256 with workspace primary key)
#  preprod/production: managed_identity (Entra ID token from IMDS, no keys)
# ---------------------------------------------------------------------------
Environment="LAW_INGESTION_METHOD=${PROFILE_LF_INGESTION}"
Environment="DCE_ENDPOINT="
Environment="DCR_IMMUTABLE_ID="
Environment="DCR_STREAM_NAME=Custom-LlamaFirewallPrompts_CL"

ExecStart=${INSTALL_DIR}/venv/bin/uvicorn proxy:app \
    --host ${BIND_HOST} \
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
#  10. HEALTH CHECKS
# =============================================================================
log "Health check — Ollama..."
curl -sf http://localhost:${OLLAMA_PORT}/api/tags >/dev/null \
    && ok "Ollama  → localhost:${OLLAMA_PORT} — UP" \
    || fail "Ollama health check failed."

log "Health check — LlamaFirewall (loading PromptGuard 2 weights)..."
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
    -d "{\"model\":\"${OLLAMA_MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"What is 2 + 2?\"}]}" \
    2>/dev/null || true)

if echo "${E2E}" | jq -e '.choices[0].message.content' >/dev/null 2>&1; then
    REPLY=$(echo "${E2E}" | jq -r '.choices[0].message.content')
    ok "End-to-end passed. Reply: \"${REPLY:0:60}\""
else
    warn "End-to-end inconclusive — service running, model may still be loading."
fi

echo -e "${GREEN}
============================================================
  Setup complete! [Profile: ${PROFILE}]
============================================================${NC}
  ollama.service        → localhost:${OLLAMA_PORT}
  llamafirewall.service → localhost:${FIREWALL_PORT}

  LLM model    : ${OLLAMA_MODEL}
  PG threshold : ${PG_THRESHOLD}
  Output scan  : ${OUTPUT_SCAN}

  Useful commands:
    journalctl -u llamafirewall -f -o cat   # live security logs
    sudo systemctl status llamafirewall     # service status
    curl -sf http://localhost:${FIREWALL_PORT}/health  # check active scanners

  From your laptop:
    ssh -N -L 8080:localhost:8080 ${SERVICE_USER}@<vm-fqdn>
"
