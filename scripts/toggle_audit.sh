#!/usr/bin/env bash
# =============================================================================
#  LlamaFirewall — Audit Mode Toggle
#
#  Enables or disables audit mode on the VM. When audit mode is ON, the full
#  scanner stack runs normally — but BLOCK decisions are NOT enforced. Traffic
#  passes through to Foundry regardless of scan result. All would-be blocks
#  are logged to Sentinel as WOULD_BLOCK for monitoring and false-positive
#  analysis.
#
#  Use before enabling enforcement to validate detection accuracy.
#  Set a concrete exit criterion before enabling:
#    "false positive rate < 1% over 2 weeks → flip to enforcement"
#
#  Usage:
#    ./toggle_audit.sh on     [vm-host]  — enable audit mode (log only, no blocks)
#    ./toggle_audit.sh off    [vm-host]  — disable audit mode (enforcement active)
#    ./toggle_audit.sh status [vm-host]  — show current state
#
#  vm-host defaults to: azureuser@lf-nprd-vm (preprod)
#  For production: ./toggle_audit.sh on azureuser@<prod-vm-ip>
#
#  ⚠️  AUDIT MODE vs BYPASS MODE:
#    Audit mode  — scanners run, blocks logged but not enforced
#    Bypass mode — scanners skipped entirely, nothing logged
#    Never enable both simultaneously.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

ACTION="${1:-status}"
VM_HOST="${2:-azureuser@lf-nprd-vm}"

case "${ACTION}" in
    on)
        echo -e "${YELLOW}"
        echo "  ⚠️  Enabling audit mode — scanning runs but blocks are NOT enforced."
        echo "      All would-be blocks will be logged as WOULD_BLOCK in Sentinel."
        echo "      Set an exit criterion before enabling:"
        echo "      'false positive rate < 1% over 2 weeks → flip to enforcement'"
        echo -e "${NC}"
        read -rp "  Are you sure? [y/N] " CONFIRM
        [[ "${CONFIRM,,}" == "y" ]] || { echo "Aborted."; exit 0; }

        # Safety check — don't enable audit mode while bypass is on
        HEALTH=$(ssh "${VM_HOST}" 'curl -sf http://localhost:8080/health' 2>/dev/null || echo '{}')
        BYPASS=$(echo "${HEALTH}" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d.get('bypass_mode', False))" 2>/dev/null || echo "False")
        if [[ "${BYPASS}" == "True" ]]; then
            echo -e "${RED}ERROR: Bypass mode is currently ON.${NC}"
            echo "  Disable bypass mode first: ./scripts/toggle_bypass.sh off ${VM_HOST}"
            exit 1
        fi

        echo ""
        echo -e "${CYAN}==> Enabling audit mode on ${VM_HOST}...${NC}"
        ssh "${VM_HOST}" \
            'sudo systemctl set-environment AUDIT_MODE=1 && \
             sudo systemctl restart llamafirewall && \
             sleep 3 && \
             curl -sf http://localhost:8080/health'
        echo ""
        echo -e "${YELLOW}🟡 AUDIT MODE IS ON — scanning active, blocks NOT enforced.${NC}"
        echo "   Would-be blocks logged as WOULD_BLOCK in Sentinel."
        echo "   Monitor false positives with:"
        echo "   LlamaFirewallEvents_CL | where scan_decision == 'WOULD_BLOCK'"
        echo ""
        echo "   Disable audit mode when exit criterion is met:"
        echo "   ./scripts/toggle_audit.sh off ${VM_HOST}"
        ;;

    off)
        echo -e "${CYAN}==> Disabling audit mode on ${VM_HOST}...${NC}"
        ssh "${VM_HOST}" \
            'sudo systemctl unset-environment AUDIT_MODE && \
             sudo systemctl restart llamafirewall && \
             sleep 3 && \
             curl -sf http://localhost:8080/health'
        echo ""
        echo -e "${GREEN}🟢 AUDIT MODE IS OFF — enforcement active.${NC}"
        echo "   LlamaFirewall is now blocking flagged traffic."
        echo "   Monitor blocks with:"
        echo "   LlamaFirewallEvents_CL | where scan_decision == 'BLOCK'"
        ;;

    status)
        echo -e "${CYAN}==> Checking audit status on ${VM_HOST}...${NC}"
        HEALTH=$(ssh "${VM_HOST}" 'curl -sf http://localhost:8080/health')

        AUDIT=$(echo "${HEALTH}" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d.get('audit_mode', False))")
        BYPASS=$(echo "${HEALTH}" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d.get('bypass_mode', False))")
        PROFILE=$(echo "${HEALTH}" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d.get('profile','unknown'))")
        BACKEND=$(echo "${HEALTH}" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d.get('backend','unknown'))")
        SCANNERS=$(echo "${HEALTH}" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(', '.join(d.get('scanners',[])))")

        echo ""
        if [[ "${BYPASS}" == "True" ]]; then
            echo -e "${RED}🔴 BYPASS MODE IS ON — scanning disabled entirely.${NC}"
        elif [[ "${AUDIT}" == "True" ]]; then
            echo -e "${YELLOW}🟡 AUDIT MODE IS ON — scanning active, blocks NOT enforced.${NC}"
            echo "   Profile  : ${PROFILE}"
            echo "   Backend  : ${BACKEND}"
            echo "   Scanners : ${SCANNERS}"
            echo ""
            echo "   KQL to monitor would-be blocks:"
            echo "   LlamaFirewallEvents_CL | where scan_decision == 'WOULD_BLOCK'"
        else
            echo -e "${GREEN}🟢 ENFORCEMENT MODE — scanning active, blocks enforced.${NC}"
            echo "   Profile  : ${PROFILE}"
            echo "   Backend  : ${BACKEND}"
            echo "   Scanners : ${SCANNERS}"
        fi
        ;;

    *)
        echo "Usage: ./scripts/toggle_audit.sh [on|off|status] [vm-host]"
        exit 1
        ;;
esac
