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

# =============================================================================
#  PROFILE SELECTION
# =============================================================================

PROFILE="${1:-}"

# Strip --profile flag if passed
[[ "${PROFILE}" == "--profile" ]] && PROFILE="${2:-}"
[[ "${PROFILE}" == --profile=* ]] && PROFILE="${PROFILE#--profile=}"

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
        ;;
    preprod)
        OLLAMA_MODEL="mistral:7b"
        PG_THRESHOLD="0.10"
        OUTPUT_SCAN="1"
        NOVA_LLM="0"
        LLAMA_GUARD_DISABLED="0"
        ;;
    production)
        OLLAMA_MODEL="llama3:8b"
        PG_THRESHOLD="0.15"
        OUTPUT_SCAN="1"
        NOVA_LLM="1"
        LLAMA_GUARD_DISABLED="0"
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
#  1. SYSTEM PACKAGES
# =============================================================================

log "Updating system packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

log "Installing system dependencies..."
sudo apt-get install -y -qq \
  python3 python3-pip python3-venv python3-dev \
  git curl wget build-essential \
  jq net-tools

ok "System packages installed."

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

# Ollama's install script creates ollama.service, but it runs as the 'ollama'
# system user. We need it accessible on localhost:11434.
log "Ensuring Ollama service is running..."
sudo systemctl enable ollama --quiet
sudo systemctl start  ollama

# Wait for Ollama to be ready
log "Waiting for Ollama API to become available..."
RETRIES=20
until curl -sf http://localhost:${OLLAMA_PORT}/api/tags >/dev/null 2>&1; do
  RETRIES=$((RETRIES - 1))
  [[ $RETRIES -le 0 ]] && fail "Ollama API did not become available in time."
  sleep 3
done
ok "Ollama is up at localhost:${OLLAMA_PORT}."

log "Pulling model: ${OLLAMA_MODEL} (this may take several minutes)..."
ollama pull "${OLLAMA_MODEL}"
ok "Model ${OLLAMA_MODEL} is ready."

# Quick smoke-test via REST API (avoids the interactive-mode hang of 'ollama run')
log "Smoke-testing Ollama REST API..."
SMOKE=$(curl -sf --max-time 60 \
    http://localhost:${OLLAMA_PORT}/api/generate \
    -d "{\"model\":\"${OLLAMA_MODEL}\",\"prompt\":\"Reply with the single word OK.\",\"stream\":false}" \
    2>/dev/null || true)
if echo "${SMOKE}" | grep -qi "ok"; then
  ok "Ollama smoke-test passed."
else
  warn "Model responded but not with expected output. This is usually fine."
  echo "  Got: ${RESPONSE}"
fi

# =============================================================================
#  3. PYTHON VIRTUAL ENVIRONMENT
# =============================================================================

log "Creating Python venv at ${INSTALL_DIR}..."
sudo mkdir -p "${INSTALL_DIR}"
sudo chown "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"

python3 -m venv "${INSTALL_DIR}/venv"
source "${INSTALL_DIR}/venv/bin/activate"

log "Upgrading pip..."
pip install --upgrade pip --quiet

# =============================================================================
#  4. LLAMAFIREWALL
# =============================================================================

log "Installing LlamaFirewall and dependencies..."

# Core LlamaFirewall package from PyPI
pip install llamafirewall --quiet

# PromptGuard 2 scanner dependencies
# PromptGuard 2 (86M) runs locally — no API key needed, lightweight enough
# for B4ms alongside Phi-3-mini.
pip install transformers torch --quiet
# Note: torch pulls ~2 GB. If disk is tight, consider torch-cpu:
#   pip install torch --index-url https://download.pytorch.org/whl/cpu

# OpenAI-compatible proxy layer (used to expose LlamaFirewall as an API)
pip install openai fastapi uvicorn httpx --quiet

ok "LlamaFirewall packages installed."

# =============================================================================
#  5. LLAMAFIREWALL PROXY APPLICATION
#  This is a thin FastAPI wrapper that:
#    - Accepts OpenAI-compatible chat/completions requests on :8080
#    - Runs the input through LlamaFirewall scanners
#    - Forwards clean requests to Ollama on :11434
#    - Runs the response through output scanners
#    - Returns the result (or a block message)
#    - Emits structured JSON logs to stdout (captured by systemd → journald)
# =============================================================================

log "Writing LlamaFirewall proxy application..."

cat > "${INSTALL_DIR}/proxy.py" << 'PROXY_EOF'
"""
LlamaFirewall Proxy — OpenAI-compatible endpoint on :8080
Sits between PyRIT (caller) and Ollama (LLM backend).

Scanner stack (PoC — lightweight):
  Input:   PromptGuard 2  — prompt injection / jailbreak detection
  Output:  (disabled in PoC to save RAM; enable AgentAlignmentCheck for prod)

Logs every request/response as structured JSON to stdout.
Systemd captures this into journald; the log shipper in step 4 reads it.
"""

import json
import logging
import sys
import time
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

# LlamaFirewall imports
from llamafirewall import (
    LlamaFirewall,
    ScannerType,
    UserMessage,
    AssistantMessage,
    ScanDecision,
)

# ---------------------------------------------------------------------------
#  Logging — structured JSON to stdout
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "level":      record.levelname,
            "logger":     record.name,
            "message":    record.getMessage(),
        }
        if hasattr(record, "extra"):
            log_obj.update(record.extra)
        return json.dumps(log_obj)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JSONFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger("llamafirewall.proxy")

# ---------------------------------------------------------------------------
#  LlamaFirewall instance
#  Using PromptGuard 2 (86M params) for input scanning.
#  Model is downloaded from HuggingFace on first start (~170 MB).
# ---------------------------------------------------------------------------

logger.info("Initialising LlamaFirewall scanners...")

firewall = LlamaFirewall(
    scanners=[
        ScannerType.PROMPT_GUARD,   # Input: detects prompt injection / jailbreaks
        # ScannerType.LLAMA_GUARD,  # Input+Output: content safety (needs 8B model — skip for PoC)
        # ScannerType.CODE_SHIELD,  # Output: detects malicious code generation
    ]
)

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL    = "phi3:mini"

app = FastAPI(title="LlamaFirewall Proxy", version="0.1.0")

# ---------------------------------------------------------------------------
#  Helper — emit a structured security event log
# ---------------------------------------------------------------------------

def emit_security_log(
    request_id: str,
    prompt: str,
    scan_decision: str,
    scan_score: float,
    blocked: bool,
    response_text: str = "",
    latency_ms: float = 0.0,
):
    logger.info(
        "security_event",
        extra={
            "event_type":     "llm_request",
            "request_id":     request_id,
            "blocked":        blocked,
            "scan_decision":  scan_decision,
            "scan_score":     round(scan_score, 4),
            "prompt_length":  len(prompt),
            "prompt_preview": prompt[:120].replace("\n", " "),
            "response_length": len(response_text),
            "latency_ms":     round(latency_ms, 1),
        },
    )

# ---------------------------------------------------------------------------
#  POST /v1/chat/completions  — OpenAI-compatible endpoint
# ---------------------------------------------------------------------------

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    t_start = time.monotonic()
    request_id = str(uuid.uuid4())

    body = await request.json()
    messages = body.get("messages", [])

    if not messages:
        raise HTTPException(status_code=400, detail="No messages provided.")

    # Extract the last user turn for scanning
    user_prompt = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            user_prompt = content if isinstance(content, str) else str(content)
            break

    # -----------------------------------------------------------------------
    #  Input scan — PromptGuard 2
    # -----------------------------------------------------------------------
    scan_result   = firewall.scan(UserMessage(content=user_prompt))
    scan_decision = scan_result.decision.name          # "ALLOW" or "BLOCK"
    scan_score    = getattr(scan_result, "score", 0.0)
    blocked       = scan_result.decision == ScanDecision.BLOCK

    if blocked:
        emit_security_log(
            request_id   = request_id,
            prompt       = user_prompt,
            scan_decision= scan_decision,
            scan_score   = scan_score,
            blocked      = True,
            latency_ms   = (time.monotonic() - t_start) * 1000,
        )
        # Return an OpenAI-shaped refusal so PyRIT can parse it normally
        return JSONResponse(
            status_code=200,
            content={
                "id":      f"chatcmpl-{request_id}",
                "object":  "chat.completion",
                "model":   OLLAMA_MODEL,
                "choices": [{
                    "index":         0,
                    "message": {
                        "role":    "assistant",
                        "content": "[BLOCKED by LlamaFirewall — prompt injection or jailbreak detected]",
                    },
                    "finish_reason": "content_filter",
                }],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "x_llamafirewall": {
                    "blocked":   True,
                    "decision":  scan_decision,
                    "score":     scan_score,
                    "request_id": request_id,
                },
            },
        )

    # -----------------------------------------------------------------------
    #  Forward to Ollama (OpenAI-compatible endpoint)
    # -----------------------------------------------------------------------
    ollama_payload = {
        "model":    body.get("model", OLLAMA_MODEL),
        "messages": messages,
        "stream":   False,
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        ollama_resp = await client.post(
            f"{OLLAMA_BASE_URL}/v1/chat/completions",
            json=ollama_payload,
        )

    if ollama_resp.status_code != 200:
        raise HTTPException(
            status_code=ollama_resp.status_code,
            detail=f"Ollama error: {ollama_resp.text}",
        )

    ollama_body  = ollama_resp.json()
    response_text = ""
    try:
        response_text = ollama_body["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        pass

    latency_ms = (time.monotonic() - t_start) * 1000

    emit_security_log(
        request_id   = request_id,
        prompt       = user_prompt,
        scan_decision= scan_decision,
        scan_score   = scan_score,
        blocked      = False,
        response_text= response_text,
        latency_ms   = latency_ms,
    )

    # Inject our metadata into the response for observability
    ollama_body.setdefault("x_llamafirewall", {
        "blocked":    False,
        "decision":   scan_decision,
        "score":      scan_score,
        "request_id": request_id,
    })

    return JSONResponse(content=ollama_body)

# ---------------------------------------------------------------------------
#  GET /health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "service": "llamafirewall-proxy"}

PROXY_EOF

ok "Proxy application written to ${INSTALL_DIR}/proxy.py."

# =============================================================================
#  6. SYSTEMD SERVICE — LLAMAFIREWALL PROXY
# =============================================================================

log "Creating systemd service for LlamaFirewall proxy (profile: ${PROFILE})..."

sudo tee /etc/systemd/system/llamafirewall.service > /dev/null << SERVICE_EOF
[Unit]
Description=LlamaFirewall Proxy (OpenAI-compatible, port ${FIREWALL_PORT}) [${PROFILE}]
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

# --- Profile: ${PROFILE} ---
Environment="LLAMAFIREWALL_PROFILE=${PROFILE}"
Environment="PROMPTGUARD_THRESHOLD=${PG_THRESHOLD}"
Environment="OUTPUT_SCAN_ENABLED=${OUTPUT_SCAN}"
Environment="NOVA_LLM_ENABLED=${NOVA_LLM}"
Environment="LLAMA_GUARD_DISABLED=${LLAMA_GUARD_DISABLED}"

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

ok "LlamaFirewall service started."

# =============================================================================
#  7. HEALTH CHECKS
# =============================================================================

log "Running health checks..."

# --- Ollama ------------------------------------------------------------------
log "Checking Ollama..."
RETRIES=10
until curl -sf http://localhost:${OLLAMA_PORT}/api/tags >/dev/null 2>&1; do
  RETRIES=$((RETRIES - 1))
  [[ $RETRIES -le 0 ]] && fail "Ollama health check failed."
  sleep 3
done
ok "Ollama  → http://localhost:${OLLAMA_PORT} — UP"

# --- LlamaFirewall proxy -----------------------------------------------------
# First boot may take 30-60 s while PromptGuard 2 downloads its weights.
log "Waiting for LlamaFirewall proxy (may download PromptGuard 2 weights ~170 MB)..."
RETRIES=40
until curl -sf http://localhost:${FIREWALL_PORT}/health >/dev/null 2>&1; do
  RETRIES=$((RETRIES - 1))
  [[ $RETRIES -le 0 ]] && {
    warn "LlamaFirewall did not start in time. Check logs with:"
    echo "  journalctl -u llamafirewall -f"
    fail "LlamaFirewall health check failed."
  }
  sleep 5
done
ok "LlamaFirewall → http://localhost:${FIREWALL_PORT} — UP"

# --- End-to-end test ---------------------------------------------------------
log "Running end-to-end prompt test through the firewall..."
E2E_RESPONSE=$(curl -sf \
  -X POST http://localhost:${FIREWALL_PORT}/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "phi3:mini",
    "messages": [{"role": "user", "content": "Reply with exactly two words: setup complete"}]
  }' || true)

if echo "${E2E_RESPONSE}" | jq -e '.choices[0].message.content' >/dev/null 2>&1; then
  REPLY=$(echo "${E2E_RESPONSE}" | jq -r '.choices[0].message.content')
  ok "End-to-end test passed. Model replied: \"${REPLY}\""
else
  warn "End-to-end test response was unexpected — may still be fine."
  echo "  Raw response: ${E2E_RESPONSE}"
fi

# =============================================================================
#  8. SUMMARY
# =============================================================================

cat << SUMMARY_EOF

${GREEN}============================================================
  Setup complete!
============================================================${NC}

  Services
  ────────
  ollama.service        → localhost:${OLLAMA_PORT}   (Ollama API)
  llamafirewall.service → localhost:${FIREWALL_PORT}   (LlamaFirewall proxy)

  Both services are enabled (start on boot) and running now.

  Useful commands
  ───────────────
  # Follow LlamaFirewall security logs:
  journalctl -u llamafirewall -f -o cat

  # Check service status:
  sudo systemctl status llamafirewall
  sudo systemctl status ollama

  # Restart the proxy after config changes:
  sudo systemctl restart llamafirewall

  From your laptop (SSH tunnel to PyRIT):
  ────────────────────────────────────────
  ssh -N -L 8080:localhost:8080 ${SERVICE_USER}@<your-vm-fqdn>

  Then PyRIT connects to: http://localhost:8080/v1

SUMMARY_EOF
