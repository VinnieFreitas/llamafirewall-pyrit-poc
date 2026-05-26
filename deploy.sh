#!/usr/bin/env bash
# =============================================================================
#  LlamaFirewall / PyRIT PoC — Deployment Script
#  Runs on your Linux laptop. Requires Azure CLI (az) to be installed.
#  Install guide: https://docs.microsoft.com/cli/azure/install-azure-cli
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
#  Config — edit these two values before running
# ---------------------------------------------------------------------------

RESOURCE_GROUP="rg-llamapoc"
LOCATION="eastus"           # Must match location in main.bicepparam

# ---------------------------------------------------------------------------
#  Derived values — no need to edit below this line
# ---------------------------------------------------------------------------

DEPLOYMENT_NAME="llamapoc-deploy-$(date +%Y%m%d-%H%M%S)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
#  Preflight checks
# ---------------------------------------------------------------------------

echo "==> Checking Azure CLI..."
if ! command -v az &>/dev/null; then
  echo "ERROR: Azure CLI not found. Install it with:"
  echo "  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
  exit 1
fi

echo "==> Checking login status..."
if ! az account show &>/dev/null; then
  echo "Not logged in. Running 'az login'..."
  az login
fi

SUBSCRIPTION=$(az account show --query "name" -o tsv)
echo "==> Using subscription: ${SUBSCRIPTION}"
echo ""
read -rp "Continue with this subscription? [y/N] " CONFIRM
[[ "${CONFIRM,,}" == "y" ]] || { echo "Aborted."; exit 0; }

# ---------------------------------------------------------------------------
#  Environment profile selection
# ---------------------------------------------------------------------------

echo ""
echo "============================================================"
echo "  Select environment profile:"
echo "============================================================"
echo ""
echo "  1) lab         — Standard_B8ms  (8 vCPU / 32 GB)"
echo "                   phi3:mini · 30-day LAW · auto-shutdown"
echo "                   ~\$16/month (light usage)"
echo ""
echo "  2) preprod     — Standard_D8s_v3 (8 vCPU / 32 GB)"
echo "                   mistral:7b · 30-day LAW · auto-shutdown"
echo "                   ~\$28/month (light usage)"
echo ""
echo "  3) production  — Standard_D16s_v3 (16 vCPU / 64 GB)"
echo "                   llama3:8b · 90-day LAW · no auto-shutdown"
echo "                   ~\$55/month (always on)"
echo ""
echo "  4) corp-lab    — NC4as_T4_v3 GPU + B2ms PyRIT VM"
echo "                   Two VMs · BeyondTrust access · sandbox VNet"
echo "                   ~\$45/month (light usage)"
echo "                   ⚠️  Requires NC-series quota in sandbox subscription"
echo ""
read -rp "Enter profile [1/2/3/4] (default: 1): " PROFILE_CHOICE

case "${PROFILE_CHOICE}" in
  2) PROFILE="preprod"    ;;
  3) PROFILE="production" ;;
  4) PROFILE="corp-lab"   ;;
  *) PROFILE="lab"        ;;
esac

echo ""
echo "==> Selected profile: ${PROFILE}"
echo ""

# ---------------------------------------------------------------------------
#  SSH KEY — corp-lab generates a dedicated key pair
#  Never reuse your personal home-lab key in a corporate environment.
# ---------------------------------------------------------------------------

if [[ "${PROFILE}" == "corp-lab" ]]; then
    CORP_KEY="${HOME}/.ssh/id_ed25519_llamapoc_corp"
    echo "============================================================"
    echo "  Corp-lab SSH key setup"
    echo "============================================================"
    echo ""
    if [[ -f "${CORP_KEY}" ]]; then
        echo "  Found existing corp key: ${CORP_KEY}"
        read -rp "  Use existing key? [Y/n] " USE_EXISTING
        if [[ "${USE_EXISTING,,}" == "n" ]]; then
            echo "  Generating new corp key..."
            ssh-keygen -t ed25519 -C "llamapoc-corp-lab" -f "${CORP_KEY}" -N ""
            echo "  ✓  New corp SSH key generated at ${CORP_KEY}"
        else
            echo "  ✓  Using existing corp key."
        fi
    else
        echo "  No corp key found — generating a dedicated key pair."
        echo "  ⚠️  Do NOT reuse your personal key in a corporate environment."
        echo ""
        ssh-keygen -t ed25519 -C "llamapoc-corp-lab" -f "${CORP_KEY}" -N ""
        echo "  ✓  Corp SSH key generated at ${CORP_KEY}"
    fi

    CORP_PUBLIC_KEY=$(cat "${CORP_KEY}.pub")
    echo ""
    echo "  Public key: ${CORP_PUBLIC_KEY}"
    echo ""

    # Inject the corp key into main.bicepparam
    sed -i "s|param adminPublicKey = '.*'|param adminPublicKey = '${CORP_PUBLIC_KEY}'|" \
        "${SCRIPT_DIR}/main.bicepparam"
    echo "  ✓  Corp public key injected into main.bicepparam."

    echo ""
    echo "  ⚠️  Keep ${CORP_KEY} safe — this is the only way to SSH into your corp VMs."
    echo "  Add to your SSH config for convenience:"
    echo "      Host llamapoc-corp-*"
    echo "        IdentityFile ${CORP_KEY}"
    echo "        User azureuser"
    echo ""
fi

# Update main.bicepparam with the selected profile
sed -i "s/^param profile = .*/param profile = '${PROFILE}'/" "${SCRIPT_DIR}/main.bicepparam"

# ---------------------------------------------------------------------------
#  Check that adminPublicKey has been set in the params file
# ---------------------------------------------------------------------------

if grep -q "REPLACE_WITH_YOUR_PUBLIC_KEY" "${SCRIPT_DIR}/main.bicepparam"; then
  echo ""
  echo "ERROR: You haven't set adminPublicKey in main.bicepparam."
  echo "  Run:  cat ~/.ssh/id_ed25519.pub"
  echo "  Then paste the output into main.bicepparam and re-run this script."
  echo ""
  echo "  No SSH key yet? Generate one with:"
  echo "    ssh-keygen -t ed25519 -C 'llamapoc'"
  exit 1
fi

# ---------------------------------------------------------------------------
#  Create Resource Group (idempotent)
# ---------------------------------------------------------------------------

echo ""
echo "==> Creating resource group '${RESOURCE_GROUP}' in '${LOCATION}'..."
az group create \
  --name     "${RESOURCE_GROUP}" \
  --location "${LOCATION}" \
  --output   none

# ---------------------------------------------------------------------------
#  Deploy
# ---------------------------------------------------------------------------

echo ""
echo "==> Starting deployment '${DEPLOYMENT_NAME}'..."
echo "    This takes about 2-3 minutes."
echo ""

DEPLOY_OUTPUT=$(az deployment group create \
  --name                  "${DEPLOYMENT_NAME}" \
  --resource-group        "${RESOURCE_GROUP}" \
  --template-file         "${SCRIPT_DIR}/main.bicep" \
  --parameters            "${SCRIPT_DIR}/main.bicepparam" \
  --query                 "properties.outputs" \
  --output                json)

# ---------------------------------------------------------------------------
#  Print outputs
# ---------------------------------------------------------------------------

echo ""
echo "============================================================"
echo "  Deployment complete! Save these values."
echo "============================================================"
echo ""

VM_IP=$(echo "${DEPLOY_OUTPUT}"          | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['vmPublicIP']['value'])")
VM_FQDN=$(echo "${DEPLOY_OUTPUT}"        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['vmFQDN']['value'])")
SSH_CMD=$(echo "${DEPLOY_OUTPUT}"        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['sshCommand']['value'])")
TUNNEL=$(echo "${DEPLOY_OUTPUT}"         | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['sshTunnelCommand']['value'])")
LAW_ID=$(echo "${DEPLOY_OUTPUT}"         | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['lawWorkspaceId']['value'])")
PROFILE_USED=$(echo "${DEPLOY_OUTPUT}"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('activeProfile',{}).get('value','lab'))")
VM_SIZE_USED=$(echo "${DEPLOY_OUTPUT}"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('vmSizeUsed',{}).get('value',''))")
PROFILE_DESC=$(echo "${DEPLOY_OUTPUT}"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('profileDescription',{}).get('value',''))")

echo "  Profile        : ${PROFILE_USED} — ${PROFILE_DESC}"
echo "  VM Size        : ${VM_SIZE_USED}"
echo "  VM Public IP   : ${VM_IP}"
echo "  VM FQDN        : ${VM_FQDN}"
echo ""
echo "  SSH connect    : ${SSH_CMD}"

# corp-lab: also print PyRIT VM details
PYRIT_IP=$(echo "${DEPLOY_OUTPUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('pyritVMPublicIP',{}).get('value','n/a'))" 2>/dev/null || echo "n/a")
PYRIT_SSH=$(echo "${DEPLOY_OUTPUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('pyritSSHCommand',{}).get('value','n/a'))" 2>/dev/null || echo "n/a")
LF_PRIVATE=$(echo "${DEPLOY_OUTPUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('llamafirewallPrivateIP',{}).get('value','n/a'))" 2>/dev/null || echo "n/a")

if [[ "${PYRIT_IP}" != "n/a" && "${PYRIT_IP}" != "" ]]; then
    echo ""
    echo "  --- PyRIT VM (corp-lab) ---"
    echo "  PyRIT VM IP    : ${PYRIT_IP}"
    echo "  PyRIT SSH      : ${PYRIT_SSH}"
    echo "  LF Private IP  : ${LF_PRIVATE}"
    echo "  (PyRIT connects to LlamaFirewall at: http://${LF_PRIVATE}:8080/v1)"
fi
echo "  SSH tunnel     : ${TUNNEL}"
echo ""
echo "  LAW Workspace  : ${LAW_ID}"
echo ""
echo "  (Full JSON outputs saved to: deploy-outputs.json)"
echo "============================================================"
echo ""

# Save outputs to file for later steps
echo "${DEPLOY_OUTPUT}" | python3 -m json.tool > "${SCRIPT_DIR}/deploy-outputs.json"

# ---------------------------------------------------------------------------
#  Reminder: get the LAW primary key (needed for step 4 log shipper)
# ---------------------------------------------------------------------------

echo "==> Fetching Log Analytics Workspace primary key..."
LAW_NAME=$(az monitor log-analytics workspace list \
  --resource-group "${RESOURCE_GROUP}" \
  --query "[0].name" -o tsv)

LAW_KEY=$(az monitor log-analytics workspace get-shared-keys \
  --resource-group "${RESOURCE_GROUP}" \
  --workspace-name  "${LAW_NAME}" \
  --query "primarySharedKey" -o tsv)

echo ""
echo "  LAW Primary Key: ${LAW_KEY}"
echo "  (Also saved to deploy-outputs.json)"
echo ""
echo "⚠️  Keep these values private — do not commit them to git."

# Append key to outputs file
python3 - <<EOF
import json, pathlib

p = pathlib.Path("${SCRIPT_DIR}/deploy-outputs.json")
data = json.loads(p.read_text())
data["lawPrimaryKey"] = {"value": "${LAW_KEY}"}
data["lawWorkspaceName"] = {"value": "${LAW_NAME}"}
p.write_text(json.dumps(data, indent=2))
EOF

echo ""
echo "==> Next step:"
echo "    Run the VM setup script (step 2) to install Ollama + LlamaFirewall."
echo "    SSH in first to verify connectivity:"
echo ""
echo "      ${SSH_CMD}"
echo ""

# ---------------------------------------------------------------------------
#  Clear stale SSH known_hosts entries
#  The VM got a new host key on this deployment. Remove any old entry so
#  SSH doesn't throw the "REMOTE HOST IDENTIFICATION HAS CHANGED" warning.
# ---------------------------------------------------------------------------

echo "==> Clearing stale SSH known_hosts entries for this host..."
ssh-keygen -f "${HOME}/.ssh/known_hosts" -R "${VM_FQDN}" 2>/dev/null || true
ssh-keygen -f "${HOME}/.ssh/known_hosts" -R "${VM_IP}"   2>/dev/null || true
echo "    Done. SSH will prompt to confirm the new host key on first connection."
echo ""
