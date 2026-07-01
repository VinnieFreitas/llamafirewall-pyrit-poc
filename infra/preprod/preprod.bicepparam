// =============================================================================
//  LlamaFirewall Corp Preprod — Parameters
//
//  Fill in ALL values marked ⚠️ before deploying.
//  Deploy with:
//    cd <repo-root>
//    az account set --subscription NonProduction
//    az group create --name RG-LLAMAFIREWALL-NPRD --location eastus
//    az deployment group create \
//      --resource-group RG-LLAMAFIREWALL-NPRD \
//      --template-file infra/preprod/preprod.bicep \
//      --parameters @infra/preprod/preprod.bicepparam
// =============================================================================

using './preprod.bicep'

// ⚠️  Your SSH public key.
// Check: cat ~/.ssh/id_ed25519.pub
// Generate if needed: ssh-keygen -t ed25519 -C "llamafirewall-nprd"
param adminPublicKey = 'REPLACE_WITH_YOUR_SSH_PUBLIC_KEY'

// ⚠️  Your Azure AD Object ID — grants you Key Vault Secrets Officer
// to populate secrets after deployment.
// Find it: az ad signed-in-user show --query id -o tsv
param keyVaultAdminObjectId = 'REPLACE_WITH_YOUR_OBJECT_ID'

// ⚠️  Foundry model deployment name as configured in NonProductionAI Foundry.
// Find it: Portal → NonProductionAI subscription →
//          safra-nprod-aif-eastus2 → Model deployments
param foundryDeploymentName = 'REPLACE_WITH_DEPLOYMENT_NAME'

// --- Defaults (change only if needed) ---------------------------------------

param prefix           = 'lf-nprd'
param location         = 'eastus'
param adminUsername    = 'azureuser'
param osDiskSizeGB     = 128
param autoShutdownTime = '2300'     // 23:00 UTC = 20:00 BRT

// Foundry endpoint — safra-nprod-aif-eastus2 (public access enabled)
param foundryEndpoint  = 'https://safra-nprod-aif-eastus2.openai.azure.com'
