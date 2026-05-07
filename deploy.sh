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

VM_IP=$(echo "${DEPLOY_OUTPUT}"     | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['vmPublicIP']['value'])")
VM_FQDN=$(echo "${DEPLOY_OUTPUT}"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['vmFQDN']['value'])")
SSH_CMD=$(echo "${DEPLOY_OUTPUT}"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['sshCommand']['value'])")
TUNNEL=$(echo "${DEPLOY_OUTPUT}"    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['sshTunnelCommand']['value'])")
LAW_ID=$(echo "${DEPLOY_OUTPUT}"    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['lawWorkspaceId']['value'])")

echo "  VM Public IP   : ${VM_IP}"
echo "  VM FQDN        : ${VM_FQDN}"
echo ""
echo "  SSH connect    : ${SSH_CMD}"
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
