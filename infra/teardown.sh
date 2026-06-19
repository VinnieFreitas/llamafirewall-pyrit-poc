#!/usr/bin/env bash
# =============================================================================
#  LlamaFirewall / PyRIT PoC — Teardown Script
#  Destroys all Azure resources and cleans up local state.
#
#  What this does:
#    1. Closes any open SSH tunnel
#    2. Clears SSH known_hosts entries for the VM
#    3. Deletes the Azure resource group (VM, disk, LAW, workbooks — everything)
#    4. Optionally removes deploy-outputs.json
#
#  Usage:
#    chmod +x teardown.sh && ./teardown.sh
#
#  ⚠️  This is irreversible. All Azure resources will be permanently deleted.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}==> $*${NC}"; }
ok()   { echo -e "${GREEN} ✓  $*${NC}"; }
warn() { echo -e "${YELLOW} ⚠  $*${NC}"; }

RESOURCE_GROUP="rg-llamapoc"
VM_FQDN="llamapoc-llama.eastus.cloudapp.azure.com"
TUNNEL_PID_FILE="/tmp/llamapoc_tunnel.pid"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "${RED}============================================================"
echo -e "  LlamaFirewall / PyRIT PoC — TEARDOWN"
echo -e "  This will permanently delete all Azure resources."
echo -e "============================================================${NC}"
echo ""
warn "Resource group to be deleted: ${RESOURCE_GROUP}"
warn "This includes: VM, disk, VNet, NSG, Public IP, Log Analytics"
warn "              Workspace, all ingested data, and Workbooks."
echo ""
read -rp "Are you sure you want to destroy everything? [y/N] " CONFIRM
[[ "${CONFIRM,,}" == "y" ]] || { echo "Aborted."; exit 0; }
echo ""

# ---------------------------------------------------------------------------
#  1. Close SSH tunnel (if running)
# ---------------------------------------------------------------------------
log "Closing SSH tunnel (if open)..."
if [[ -f "${TUNNEL_PID_FILE}" ]]; then
    TUNNEL_PID=$(cat "${TUNNEL_PID_FILE}")
    if kill "${TUNNEL_PID}" 2>/dev/null; then
        ok "Tunnel closed (PID ${TUNNEL_PID})."
    else
        warn "Tunnel PID ${TUNNEL_PID} was not running — skipping."
    fi
    rm -f "${TUNNEL_PID_FILE}"
else
    # Also try to find and kill any tunnel to port 8080 directly
    TUNNEL_PID=$(pgrep -f "ssh.*8080:localhost:8080" 2>/dev/null || true)
    if [[ -n "${TUNNEL_PID}" ]]; then
        kill "${TUNNEL_PID}" 2>/dev/null || true
        ok "Tunnel closed (PID ${TUNNEL_PID})."
    else
        ok "No active tunnel found."
    fi
fi

# ---------------------------------------------------------------------------
#  2. Clear SSH known_hosts entries
#  Do this BEFORE deleting the resource group so we still have the IP
#  available from deploy-outputs.json if needed.
# ---------------------------------------------------------------------------
log "Clearing SSH known_hosts entries..."

# Clear by FQDN
ssh-keygen -f "${HOME}/.ssh/known_hosts" -R "${VM_FQDN}" 2>/dev/null \
    && ok "Removed known_hosts entry for ${VM_FQDN}." \
    || warn "No known_hosts entry found for ${VM_FQDN} — already clean."

# Clear by IP (read from deploy-outputs.json if available)
OUTPUTS_FILE="${SCRIPT_DIR}/deploy-outputs.json"
if [[ -f "${OUTPUTS_FILE}" ]]; then
    VM_IP=$(python3 -c "
import json, sys
d = json.load(open('${OUTPUTS_FILE}'))
v = d.get('vmPublicIP', {})
print(v.get('value', v) if isinstance(v, dict) else v)
" 2>/dev/null || true)

    if [[ -n "${VM_IP}" ]]; then
        ssh-keygen -f "${HOME}/.ssh/known_hosts" -R "${VM_IP}" 2>/dev/null \
            && ok "Removed known_hosts entry for ${VM_IP}." \
            || warn "No known_hosts entry found for ${VM_IP} — already clean."
    fi
fi

# ---------------------------------------------------------------------------
#  3. Delete Azure resource group
# ---------------------------------------------------------------------------
log "Checking Azure login status..."
if ! az account show &>/dev/null; then
    warn "Not logged into Azure. Running 'az login'..."
    az login
fi

SUBSCRIPTION=$(az account show --query "name" -o tsv)
ok "Azure session active — subscription: ${SUBSCRIPTION}"

log "Checking if resource group '${RESOURCE_GROUP}' exists..."
if ! az group show --name "${RESOURCE_GROUP}" &>/dev/null; then
    warn "Resource group '${RESOURCE_GROUP}' not found — may already be deleted."
else
    log "Deleting resource group '${RESOURCE_GROUP}' (runs in background)..."
    az group delete \
        --name    "${RESOURCE_GROUP}" \
        --yes \
        --no-wait
    ok "Deletion queued. Azure is removing all resources in the background."
    echo "    Monitor progress:"
    echo "    az group show --name ${RESOURCE_GROUP} --query properties.provisioningState -o tsv"
    echo "    (Returns 'Deleting...' then 'not found' when complete — ~3-5 minutes)"
fi

# ---------------------------------------------------------------------------
#  4. Remove deploy-outputs.json (optional)
# ---------------------------------------------------------------------------
echo ""
if [[ -f "${OUTPUTS_FILE}" ]]; then
    read -rp "Remove deploy-outputs.json (contains LAW key, no longer valid)? [Y/n] " REMOVE_OUTPUTS
    if [[ "${REMOVE_OUTPUTS,,}" != "n" ]]; then
        rm -f "${OUTPUTS_FILE}"
        ok "deploy-outputs.json removed."
    else
        warn "deploy-outputs.json kept — remember it contains secrets for a now-deleted workspace."
    fi
fi

# ---------------------------------------------------------------------------
#  Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}============================================================"
echo -e "  Teardown complete."
echo -e "============================================================${NC}"
echo ""
echo "  SSH known_hosts : cleared"
echo "  SSH tunnel      : closed"
echo "  Azure resources : deletion in progress (~3-5 min)"
echo ""
echo "  To rebuild from scratch, run:"
echo "    ./deploy.sh"
echo ""
