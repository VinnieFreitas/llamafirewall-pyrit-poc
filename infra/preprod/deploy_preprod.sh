#!/usr/bin/env bash
# =============================================================================
#  LlamaFirewall Corp Preprod — Deployment Script
#  Subscription: NonProduction (85b72874-7e81-40c7-b857-2ad4d9e07faa)
#  Resource Group: RG-LLAMAFIREWALL-NPRD
#  Region: eastus
#
#  Prerequisites:
#    1. NC quota approved in eastus for NonProduction subscription
#    2. infra/preprod/preprod.bicepparam filled in (SSH key, object ID, model name)
#    3. az login completed and NonProduction subscription accessible
#
#  Usage:
#    chmod +x infra/preprod/deploy_preprod.sh
#    ./infra/preprod/deploy_preprod.sh
# =============================================================================

set -euo pipefail

SUBSCRIPTION_ID="85b72874-7e81-40c7-b857-2ad4d9e07faa"
RESOURCE_GROUP="RG-LLAMAFIREWALL-NPRD"
LOCATION="eastus"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUTS_FILE="${SCRIPT_DIR}/preprod-outputs.json"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${CYAN}==> $*${NC}"; }
ok()   { echo -e "${GREEN} ✓  $*${NC}"; }
warn() { echo -e "${YELLOW} ⚠️  $*${NC}"; }
fail() { echo -e "${RED}ERROR: $*${NC}"; exit 1; }

# ---------------------------------------------------------------------------
#  Preflight checks
# ---------------------------------------------------------------------------
log "Preflight checks..."

# Check params file is filled in
if grep -q "REPLACE_WITH" "${SCRIPT_DIR}/preprod.bicepparam"; then
  fail "preprod.bicepparam contains unfilled placeholders.\n  Run: grep 'REPLACE_WITH' infra/preprod/preprod.bicepparam"
fi

# Check NC quota
log "Checking NC quota in ${LOCATION}..."
QUOTA=$(az vm list-usage \
  --location "${LOCATION}" \
  --subscription "${SUBSCRIPTION_ID}" \
  --query "[?name.value=='standardNCASv3_T4FamilyvCPUs'].{current:currentValue, limit:limit}" \
  --output json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
if d: print(f\"{d[0]['current']}/{d[0]['limit']}\")
else: print('NOT_FOUND')
")

if [[ "${QUOTA}" == "NOT_FOUND" ]]; then
  warn "Could not read NC quota — proceeding anyway. Deployment will fail if quota is 0."
elif [[ "${QUOTA}" == 0/* ]]; then
  fail "Standard NCASv3_T4 vCPU quota is 0 in ${LOCATION}.\n  Request quota at: Portal → Subscriptions → NonProduction → Usage + quotas"
else
  ok "NC quota: ${QUOTA} vCPUs (need 8 for NC8as_T4_v3)"
fi

# ---------------------------------------------------------------------------
#  Switch to NonProduction subscription
# ---------------------------------------------------------------------------
log "Setting subscription to NonProduction..."
az account set --subscription "${SUBSCRIPTION_ID}"
CURRENT=$(az account show --query name -o tsv)
ok "Active subscription: ${CURRENT}"

# ---------------------------------------------------------------------------
#  Create Resource Group
# ---------------------------------------------------------------------------
log "Creating resource group ${RESOURCE_GROUP} in ${LOCATION}..."
az group create \
  --name     "${RESOURCE_GROUP}" \
  --location "${LOCATION}" \
  --output   none
ok "Resource group ready."

# ---------------------------------------------------------------------------
#  Deploy Bicep
# ---------------------------------------------------------------------------
log "Deploying preprod.bicep — this takes ~15 minutes (NVIDIA driver extension)..."
echo "  VM:       Standard_NC8as_T4_v3 (8 vCPU / 56GB RAM / T4 GPU)"
echo "  Access:   Azure Bastion Developer SKU"
echo "  Secrets:  Azure Key Vault"
echo "  Logging:  Managed Identity → DCR → Log Analytics"
echo ""

DEPLOY_OUTPUT=$(az deployment group create \
  --subscription     "${SUBSCRIPTION_ID}" \
  --resource-group   "${RESOURCE_GROUP}" \
  --template-file    "${SCRIPT_DIR}/preprod.bicep" \
  --parameters       "@${SCRIPT_DIR}/preprod.bicepparam" \
  --output json)

if [[ $? -ne 0 ]]; then
  fail "Deployment failed. Check the Azure Portal for details:\n  Portal → Resource groups → ${RESOURCE_GROUP} → Deployments"
fi

ok "Deployment succeeded."

# ---------------------------------------------------------------------------
#  Extract and save outputs
# ---------------------------------------------------------------------------
log "Extracting deployment outputs..."

python3 - << PYEOF
import json, os, sys

deploy = json.loads('''${DEPLOY_OUTPUT}''')
outputs = deploy.get('properties', {}).get('outputs', {})

def val(key):
    return outputs.get(key, {}).get('value', 'n/a')

data = {
    'vmName':               val('vmName'),
    'vmPrivateIP':          val('vmPrivateIP'),
    'vmPrincipalId':        val('vmPrincipalId'),
    'keyVaultName':         val('keyVaultName'),
    'keyVaultUri':          val('keyVaultUri'),
    'lawWorkspaceId':       val('lawWorkspaceId'),
    'lawResourceId':        val('lawResourceId'),
    'dceEndpoint':          val('dceEndpoint'),
    'dcrImmutableId':       val('dcrImmutableId'),
    'dcrStreamName':        val('dcrStreamName'),
    'foundryEndpoint':      val('foundryEndpoint'),
    'foundryDeploymentName':val('foundryDeploymentName'),
    'vnetResourceId':       val('vnetResourceId'),
    'vnetAddressSpace':     val('vnetAddressSpace'),
}

outputs_path = '${OUTPUTS_FILE}'
with open(outputs_path, 'w') as f:
    json.dump(data, f, indent=2)

print(f"""
============================================================
  Deployment complete.
============================================================

  VM Name        : {data['vmName']}
  VM Private IP  : {data['vmPrivateIP']}
  Key Vault      : {data['keyVaultName']}
  LAW Workspace  : {data['lawWorkspaceId']}
  DCE Endpoint   : {data['dceEndpoint']}
  DCR ID         : {data['dcrImmutableId']}

  Foundry Target : {data['foundryEndpoint']}
  Model Deploy   : {data['foundryDeploymentName']}

  VNet ID        : {data['vnetResourceId']}
  VNet Space     : {data['vnetAddressSpace']}
  (Provide VNet ID + address space to networking team for peering)

  Outputs saved to: {outputs_path}
""")
PYEOF

# ---------------------------------------------------------------------------
#  Post-deployment: populate Key Vault secrets
# ---------------------------------------------------------------------------
KV_NAME=$(python3 -c "import json; print(json.load(open('${OUTPUTS_FILE}'))['keyVaultName'])")

echo ""
warn "Next step: populate Key Vault secrets."
echo ""
echo "  The VM's Managed Identity can now read secrets from Key Vault."
echo "  You need to add three secrets before running setup_vm.sh:"
echo ""
echo "  1. HuggingFace token (for PromptGuard 2 model download):"
echo "     az keyvault secret set --vault-name ${KV_NAME} --name hf-token --value <hf_xxx>"
echo ""
echo "  2. Log Analytics Workspace ID (for Sentinel logging):"
LAW_ID=$(python3 -c "import json; print(json.load(open('${OUTPUTS_FILE}'))['lawWorkspaceId'])")
echo "     az keyvault secret set --vault-name ${KV_NAME} --name sentinel-law-id --value ${LAW_ID}"
echo "     (Value already known — copy-paste the command above)"
echo ""
echo "  3. Foundry API key (if using key-based auth vs Managed Identity):"
echo "     az keyvault secret set --vault-name ${KV_NAME} --name foundry-api-key --value <key>"
echo "     Find key: Portal → NonProductionAI → safra-nprod-aif-eastus2 → Keys"
echo ""
echo "  Then SSH to the VM via Bastion:"
echo "     Portal → Resource groups → ${RESOURCE_GROUP} → ${KV_NAME%-kv}-vm → Connect → Bastion"
echo ""
echo "  And run setup:"
echo "     bash <(curl -sf https://raw.githubusercontent.com/VinnieFreitas/llamafirewall-pyrit-poc/main/infra/setup_vm.sh) --profile preprod --corp"
echo ""
warn "preprod-outputs.json contains workspace credentials. It is gitignored — do not commit it."
