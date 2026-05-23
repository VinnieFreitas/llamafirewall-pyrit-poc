#!/usr/bin/env bash
# =============================================================================
#  LlamaFirewall — Bypass Mode Toggle
#
#  Enables or disables bypass mode on the VM. When bypass is ON, all scanning
#  is skipped and prompts are forwarded directly to Ollama. The proxy stays
#  running and the endpoint stays the same — no network changes needed.
#
#  Use during production incidents where legitimate traffic is being dropped.
#  Always disable and investigate root cause before re-enabling scanning.
#
#  Usage:
#    ./toggle_bypass.sh on    [vm-host]   — disable all scanning
#    ./toggle_bypass.sh off   [vm-host]   — re-enable scanning
#    ./toggle_bypass.sh status [vm-host]  — show current state
#
#  vm-host defaults to: azureuser@llamapoc-llama.eastus.cloudapp.azure.com
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

ACTION="${1:-status}"
VM_HOST="${2:-azureuser@llamapoc-llama.eastus.cloudapp.azure.com}"

case "${ACTION}" in
    on)
        echo -e "${YELLOW}"
        echo "  ⚠️  WARNING: Enabling bypass mode disables ALL LlamaFirewall scanning."
        echo "      Prompts will be forwarded to Ollama without any security checks."
        echo "      Use only during incidents. Investigate and re-enable ASAP."
        echo -e "${NC}"
        read -rp "  Are you sure? [y/N] " CONFIRM
        [[ "${CONFIRM,,}" == "y" ]] || { echo "Aborted."; exit 0; }

        echo ""
        echo -e "${CYAN}==> Enabling bypass mode on ${VM_HOST}...${NC}"
        ssh "${VM_HOST}" \
            'sudo systemctl set-environment BYPASS_MODE=1 && \
             sudo systemctl restart llamafirewall && \
             sleep 3 && \
             curl -sf http://localhost:8080/health'
        echo ""
        echo -e "${RED}🔴 BYPASS MODE IS ON — scanning disabled.${NC}"
        echo "   All prompts are forwarded directly to Ollama."
        echo "   Re-enable scanning when incident is resolved:"
        echo "   ./toggle_bypass.sh off ${VM_HOST}"
        ;;

    off)
        echo -e "${CYAN}==> Disabling bypass mode on ${VM_HOST}...${NC}"
        ssh "${VM_HOST}" \
            'sudo systemctl unset-environment BYPASS_MODE && \
             sudo systemctl restart llamafirewall && \
             sleep 3 && \
             curl -sf http://localhost:8080/health'
        echo ""
        echo -e "${GREEN}🟢 BYPASS MODE IS OFF — scanning restored.${NC}"
        echo "   All prompts are now scanned by the full 6-layer stack."
        ;;

    status)
        echo -e "${CYAN}==> Checking bypass status on ${VM_HOST}...${NC}"
        HEALTH=$(ssh "${VM_HOST}" 'curl -sf http://localhost:8080/health')
        BYPASS=$(echo "${HEALTH}" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d.get('bypass_mode', False))")
        PROFILE=$(echo "${HEALTH}" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d.get('profile','unknown'))")
        SCANNERS=$(echo "${HEALTH}" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(', '.join(d.get('scanners',[])))")

        echo ""
        if [[ "${BYPASS}" == "True" ]]; then
            echo -e "${RED}🔴 BYPASS MODE IS ON${NC}"
            echo "   Scanning is DISABLED — prompts forwarded directly to Ollama."
        else
            echo -e "${GREEN}🟢 BYPASS MODE IS OFF${NC}"
            echo "   Profile  : ${PROFILE}"
            echo "   Scanners : ${SCANNERS}"
        fi
        ;;

    *)
        echo "Usage: ./toggle_bypass.sh [on|off|status] [vm-host]"
        exit 1
        ;;
esac
