#!/usr/bin/env bash
# =============================================================================
#  LlamaFirewall / PyRIT PoC — NO_LLM Mode Toggle
#
#  Toggles Ollama bypass on the VM. Use during PyRIT red-team runs when
#  you only care about LlamaFirewall decisions, not LLM responses.
#
#  NO_LLM ON  → PromptGuard scan only (~1-2s per prompt)
#  NO_LLM OFF → PromptGuard scan + Ollama response (~10-30s per prompt)
#
#  Usage:
#    ./toggle_nollm.sh on   azureuser@llamapoc-llama.eastus.cloudapp.azure.com
#    ./toggle_nollm.sh off  azureuser@llamapoc-llama.eastus.cloudapp.azure.com
#    ./toggle_nollm.sh      azureuser@llamapoc-llama.eastus.cloudapp.azure.com
#    (no argument = show current status)
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

ACTION="${1:-status}"
VM_HOST="${2:-azureuser@llamapoc-llama.eastus.cloudapp.azure.com}"

case "${ACTION}" in
    on)
        echo -e "${CYAN}==> Enabling NO_LLM mode on ${VM_HOST}...${NC}"
        ssh "${VM_HOST}" \
            'sudo systemctl set-environment NO_LLM=1 && \
             sudo systemctl restart llamafirewall && \
             sleep 3 && curl -sf http://localhost:8080/health'
        echo ""
        echo -e "${GREEN} ✓  NO_LLM mode ON — Ollama bypassed.${NC}"
        echo "    PyRIT scan speed: ~1-2s per prompt."
        ;;
    off)
        echo -e "${CYAN}==> Disabling NO_LLM mode on ${VM_HOST}...${NC}"
        ssh "${VM_HOST}" \
            'sudo systemctl unset-environment NO_LLM && \
             sudo systemctl restart llamafirewall && \
             sleep 3 && curl -sf http://localhost:8080/health'
        echo ""
        echo -e "${GREEN} ✓  NO_LLM mode OFF — Ollama responses enabled.${NC}"
        echo "    PyRIT scan speed: ~10-30s per prompt."
        ;;
    status)
        echo -e "${CYAN}==> Checking NO_LLM status on ${VM_HOST}...${NC}"
        STATUS=$(ssh "${VM_HOST}" \
            'sudo systemctl show-environment | grep NO_LLM || echo "NO_LLM=0"')
        if echo "${STATUS}" | grep -q "NO_LLM=1"; then
            echo -e "${YELLOW} ⚡ NO_LLM mode is ON — Ollama is being bypassed.${NC}"
        else
            echo -e "${GREEN} 🔁 NO_LLM mode is OFF — full LLM responses active.${NC}"
        fi
        ;;
    *)
        echo "Usage: ./toggle_nollm.sh [on|off|status] [vm-host]"
        echo "  on     — bypass Ollama (fast PyRIT runs)"
        echo "  off    — restore Ollama responses"
        echo "  status — show current mode (default)"
        exit 1
        ;;
esac
