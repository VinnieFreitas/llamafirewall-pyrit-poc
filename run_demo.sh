#!/usr/bin/env bash
# =============================================================================
#  LlamaFirewall / PyRIT PoC — Demo Script
#  One command that does everything for the demo video:
#    0. Preflight checks (Azure CLI, VM state, Python venv)
#    1. Start VM if deallocated (with boot wait)
#    2. Open SSH tunnel
#    3. Run PyRIT red-team (18 prompts)
#    4. Automatically ship results to Log Analytics
#    5. Print the workbook URL
#
#  Usage:
#    source venv/bin/activate
#    ./run_demo.sh
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${CYAN}[$(date +%H:%M:%S)] ==> $*${NC}"; }
ok()   { echo -e "${GREEN}[$(date +%H:%M:%S)]  ✓  $*${NC}"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)]  ⚠  $*${NC}"; }
fail() { echo -e "${RED}[$(date +%H:%M:%S)]  ✗  $*${NC}"; exit 1; }

VM_HOST="azureuser@llamapoc-llama.eastus.cloudapp.azure.com"
VM_NAME="llamapoc-vm"
RESOURCE_GROUP="rg-llamapoc"
TUNNEL_PORT=8080
TUNNEL_PID_FILE="/tmp/llamapoc_tunnel.pid"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKBOOK_URL="https://portal.azure.com/#view/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/~/workbooks"

# ---------------------------------------------------------------------------
#  PREFLIGHT CHECKS
# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}============================================================"
echo -e "  LlamaFirewall / PyRIT PoC — Demo"
echo -e "============================================================${NC}"
echo ""
log "Running preflight checks..."

# 1. Azure CLI installed
if ! command -v az &>/dev/null; then
    fail "Azure CLI not found. Install: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
fi
ok "Azure CLI found."

# 2. Logged into Azure
if ! az account show &>/dev/null; then
    warn "Not logged into Azure. Running 'az login'..."
    az login
fi
SUBSCRIPTION=$(az account show --query "name" -o tsv)
ok "Azure session active — subscription: ${SUBSCRIPTION}"

# 3. Python venv active with required packages
if ! python3 -c "import pyrit" &>/dev/null; then
    fail "PyRIT not found. Activate the venv first: source venv/bin/activate"
fi
if ! python3 -c "import httpx" &>/dev/null; then
    fail "httpx not found. Activate the venv first: source venv/bin/activate"
fi
ok "Python environment ready."

# 4. deploy-outputs.json present
OUTPUTS_FILE="${SCRIPT_DIR}/../step1-infrastructure/deploy-outputs.json"
[[ ! -f "${OUTPUTS_FILE}" ]] && OUTPUTS_FILE="${SCRIPT_DIR}/deploy-outputs.json"
[[ ! -f "${OUTPUTS_FILE}" ]] && fail "deploy-outputs.json not found. Copy it from step1-infrastructure/."
ok "deploy-outputs.json found."

# ---------------------------------------------------------------------------
#  VM STATE CHECK — start it if deallocated
# ---------------------------------------------------------------------------
log "Checking VM state..."

VM_STATE=$(az vm get-instance-view \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${VM_NAME}" \
    --query "instanceView.statuses[1].displayStatus" \
    -o tsv 2>/dev/null || echo "unknown")

echo "  Current state: ${VM_STATE}"

case "${VM_STATE}" in
    "VM running")
        ok "VM is already running."
        ;;
    "VM deallocated"|"VM stopped")
        warn "VM is not running — starting it now..."
        az vm start \
            --resource-group "${RESOURCE_GROUP}" \
            --name "${VM_NAME}" \
            --no-wait

        log "Waiting for VM to boot (~90 seconds)..."
        BOOT_WAIT=0
        until ssh -o "StrictHostKeyChecking=accept-new" \
                  -o "ConnectTimeout=5" \
                  -o "BatchMode=yes" \
                  "${VM_HOST}" "exit" &>/dev/null; do
            sleep 10; BOOT_WAIT=$((BOOT_WAIT + 10)); echo -n "  ."
            [[ $BOOT_WAIT -gt 180 ]] && fail "VM did not become reachable after 3 minutes."
        done
        echo ""
        log "Waiting for services to fully start..."
        sleep 20
        ok "VM is up."
        ;;
    "VM starting")
        log "VM is already starting — waiting..."
        BOOT_WAIT=0
        until ssh -o "StrictHostKeyChecking=accept-new" \
                  -o "ConnectTimeout=5" \
                  -o "BatchMode=yes" \
                  "${VM_HOST}" "exit" &>/dev/null; do
            sleep 10; BOOT_WAIT=$((BOOT_WAIT + 10)); echo -n "  ."
            [[ $BOOT_WAIT -gt 180 ]] && fail "VM did not become reachable after 3 minutes."
        done
        echo ""
        sleep 20
        ok "VM reachable."
        ;;
    *)
        fail "Unexpected VM state: '${VM_STATE}'. Check the Azure portal."
        ;;
esac

# Verify both services are active on the VM
log "Verifying VM services (ollama + llamafirewall)..."
SERVICES=$(ssh -o "StrictHostKeyChecking=accept-new" \
    "${VM_HOST}" \
    'systemctl is-active ollama llamafirewall 2>/dev/null | tr "\n" " "' || true)

if echo "${SERVICES}" | grep -q "inactive\|failed"; then
    warn "A service is not active (${SERVICES}) — attempting restart..."
    ssh "${VM_HOST}" 'sudo systemctl restart ollama llamafirewall' || true
    sleep 10
fi
ok "Services active: ${SERVICES}"

# ---------------------------------------------------------------------------
#  OPEN SSH TUNNEL
# ---------------------------------------------------------------------------
log "Opening SSH tunnel → ${VM_HOST}:${TUNNEL_PORT}..."

if [[ -f "${TUNNEL_PID_FILE}" ]]; then
    OLD_PID=$(cat "${TUNNEL_PID_FILE}")
    kill "${OLD_PID}" 2>/dev/null || true
    rm -f "${TUNNEL_PID_FILE}"
fi

ssh -N -f \
    -L "${TUNNEL_PORT}:localhost:${TUNNEL_PORT}" \
    -o "StrictHostKeyChecking=accept-new" \
    -o "ServerAliveInterval=30" \
    "${VM_HOST}"

pgrep -n -f "ssh.*${TUNNEL_PORT}:localhost:${TUNNEL_PORT}" > "${TUNNEL_PID_FILE}" || true
sleep 2

# Verify LlamaFirewall is reachable through the tunnel
log "Verifying LlamaFirewall through tunnel..."
RETRIES=12
HEALTH=""
until echo "${HEALTH}" | grep -q "ok"; do
    HEALTH=$(curl -sf --max-time 10 http://localhost:${TUNNEL_PORT}/health 2>/dev/null || true)
    RETRIES=$((RETRIES - 1))
    [[ $RETRIES -le 0 ]] && fail "LlamaFirewall not reachable. Check: journalctl -u llamafirewall on the VM."
    [[ ! "${HEALTH}" =~ "ok" ]] && { sleep 5; echo -n "  ."; }
done
echo ""
ok "LlamaFirewall reachable at localhost:${TUNNEL_PORT}."

# ---------------------------------------------------------------------------
#  RUN PYRIT RED-TEAM
# ---------------------------------------------------------------------------
log "Starting PyRIT red-team session..."
echo ""

python3 "${SCRIPT_DIR}/../step3-pyrit/pyrit_redteam.py"

echo ""
ok "PyRIT run complete."

# ---------------------------------------------------------------------------
#  SHIP RESULTS TO LOG ANALYTICS
# ---------------------------------------------------------------------------
log "Shipping results to Azure Log Analytics..."

python3 "${SCRIPT_DIR}/../step4-log-shipper/log_shipper.py" --mode pyrit

ok "Results shipped to PyRITResults_CL."

# ---------------------------------------------------------------------------
#  CLOSE TUNNEL
# ---------------------------------------------------------------------------
log "Closing SSH tunnel..."
if [[ -f "${TUNNEL_PID_FILE}" ]]; then
    kill "$(cat ${TUNNEL_PID_FILE})" 2>/dev/null || true
    rm -f "${TUNNEL_PID_FILE}"
fi
ok "Tunnel closed."

# ---------------------------------------------------------------------------
#  DONE
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}============================================================"
echo -e "  Demo complete!"
echo -e "============================================================${NC}"
echo ""
echo "  Results are live in Log Analytics."
echo "  Allow up to 5 minutes for ingestion, then open the workbook:"
echo ""
echo -e "  ${CYAN}${WORKBOOK_URL}${NC}"
echo ""
echo "  Look for: LlamaFirewall Security Dashboard"
echo ""
