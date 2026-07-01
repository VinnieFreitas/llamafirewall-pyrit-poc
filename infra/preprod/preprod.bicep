// =============================================================================
//  LlamaFirewall — Corp Preprod Infrastructure
//  Target: NonProduction subscription / eastus / RG-LLAMAFIREWALL-NPRD
//
//  VM:       Standard_NC8as_T4_v3 (8 vCPU, 56GB RAM, 1× T4 16GB VRAM)
//  Access:   Azure Bastion Developer SKU (no public IP)
//  Secrets:  Azure Key Vault (HF token, Sentinel workspace key)
//  Logging:  Managed Identity → DCR → LAW (LlamaFirewallPrompts_CL)
//  Target:   safra-nprod-aif-eastus2 (NonProductionAI sub)
//
//  ⚠️  Requires Standard NCASv3_T4 Family vCPU quota in eastus.
//      Request at: Portal → Subscriptions → NonProduction →
//      Usage + quotas → Standard NCASv3_T4 → Request increase (8 vCPUs)
//
//  Deployment:
//    az deployment group create \
//      --subscription 85b72874-7e81-40c7-b857-2ad4d9e07faa \
//      --resource-group RG-LLAMAFIREWALL-NPRD \
//      --template-file infra/preprod/preprod.bicep \
//      --parameters @infra/preprod/preprod.bicepparam
// =============================================================================

// ---------------------------------------------------------------------------
//  Parameters
// ---------------------------------------------------------------------------

@description('Short prefix applied to every resource name.')
@minLength(3)
@maxLength(10)
param prefix string = 'lf-nprd'

@description('Azure region. Must match where NC quota was approved.')
param location string = 'eastus'

@description('Admin username for the VM.')
param adminUsername string = 'azureuser'

@description('SSH public key (contents of ~/.ssh/id_ed25519.pub).')
param adminPublicKey string

@description('OS disk size in GB. 128GB recommended for model weight cache.')
param osDiskSizeGB int = 128

@description('Daily auto-shutdown time in UTC (HHmm). São Paulo is UTC-3.')
param autoShutdownTime string = '2300'

@description('''
NonProductionAI Foundry endpoint URL.
Format: https://<resource>.openai.azure.com
Default: safra-nprod-aif-eastus2 (public access enabled — no VNet peering needed).
''')
param foundryEndpoint string = 'https://safra-nprod-aif-eastus2.openai.azure.com'

@description('Foundry model deployment name (as configured in NonProductionAI Foundry).')
param foundryDeploymentName string = 'gpt-4o'

@description('Object ID of the user or group that should have Key Vault Secrets Officer role.')
param keyVaultAdminObjectId string

// ---------------------------------------------------------------------------
//  Variables
// ---------------------------------------------------------------------------

var vmName        = '${prefix}-vm'
var nicName       = '${prefix}-nic'
var diskName      = '${prefix}-osdisk'
var nsgName       = '${prefix}-nsg'
var vnetName      = '${prefix}-vnet'
var lawName       = '${prefix}-law'
var dceName       = '${prefix}-dce'
var dcrName       = '${prefix}-dcr-prompts'
var kvName        = '${prefix}-kv'
var bastionName   = '${prefix}-bastion'
var subnetName    = 'llamafirewall-subnet'

// Built-in roles
var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'
var keyVaultSecretsUserRoleId        = '4633458b-17de-408a-b874-0445c86b69e6'
var keyVaultSecretsOfficerRoleId     = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'

// ---------------------------------------------------------------------------
//  Log Analytics Workspace
//  Preprod uses Managed Identity + DCR — no static workspace key on the VM.
// ---------------------------------------------------------------------------

resource law 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name:     lawName
  location: location
  properties: {
    sku:             { name: 'PerGB2018' }
    retentionInDays: 30
    features: {
      disableLocalAuth:                            false
      enableLogAccessUsingOnlyResourcePermissions: false
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery:     'Enabled'
  }
}

// ---------------------------------------------------------------------------
//  Data Collection Endpoint — required for DCR-based ingestion
// ---------------------------------------------------------------------------

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' = {
  name:     dceName
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// ---------------------------------------------------------------------------
//  Data Collection Rule — LlamaFirewallPrompts_CL schema
//  Matches the fields emitted by proxy.py::_ship_prompt_to_law()
// ---------------------------------------------------------------------------

resource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name:     dcrName
  location: location
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      'Custom-LlamaFirewallPrompts_CL': {
        columns: [
          { name: 'TimeGenerated',   type: 'datetime' }
          { name: 'request_id',      type: 'string'   }
          { name: 'user_id',         type: 'string'   }
          { name: 'source',          type: 'string'   }
          { name: 'profile',         type: 'string'   }
          { name: 'full_prompt',     type: 'string'   }
          { name: 'prompt_length',   type: 'int'      }
          { name: 'message_count',   type: 'int'      }
          { name: 'scan_decision',   type: 'string'   }
          { name: 'scan_score',      type: 'real'     }
          { name: 'scan_reason',     type: 'string'   }
          { name: 'blocked',         type: 'boolean'  }
          { name: 'latency_ms',      type: 'real'     }
          { name: 'pii_redacted',    type: 'boolean'  }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: law.id
          name:                'law-destination'
        }
      ]
    }
    dataFlows: [
      {
        streams:      [ 'Custom-LlamaFirewallPrompts_CL' ]
        destinations: [ 'law-destination' ]
        outputStream: 'Custom-LlamaFirewallPrompts_CL'
        transformKql: 'source'
      }
    ]
  }
}

// ---------------------------------------------------------------------------
//  Key Vault
//  Stores:
//    - hf-token          : HuggingFace read token for PromptGuard 2
//    - sentinel-law-id   : Log Analytics Workspace ID (non-sensitive but centralised)
//    - foundry-api-key   : Foundry API key (if using key-based auth vs Managed Identity)
//
//  VM Managed Identity gets Secrets User (read-only).
//  keyVaultAdminObjectId gets Secrets Officer (read/write) for initial secret population.
//
//  ⚠️  After deployment, manually add secrets via:
//      az keyvault secret set --vault-name <kv-name> --name hf-token --value <hf_xxx>
//      az keyvault secret set --vault-name <kv-name> --name sentinel-law-id --value <workspace-id>
//      az keyvault secret set --vault-name <kv-name> --name foundry-api-key --value <key>
// ---------------------------------------------------------------------------

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name:     kvName
  location: location
  properties: {
    sku: {
      family: 'A'
      name:   'standard'
    }
    tenantId:                      tenant().tenantId
    enableRbacAuthorization:       true        // RBAC model — no access policies
    enableSoftDelete:              true
    softDeleteRetentionInDays:     7           // minimum for nonprod
    enablePurgeProtection:         false       // allow purge in nonprod
    publicNetworkAccess:           'Enabled'   // VM reaches KV over public endpoint
    networkAcls: {
      defaultAction: 'Allow'                  // tighten to VNet when peering is in place
      bypass:        'AzureServices'
    }
  }
}

// VM Managed Identity → Key Vault Secrets User (read secrets at runtime)
resource kvSecretsUserRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name:  guid(kv.id, vm.id, keyVaultSecretsUserRoleId)
  scope: kv
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      keyVaultSecretsUserRoleId
    )
    principalId:   vm.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Admin user/group → Key Vault Secrets Officer (populate secrets post-deploy)
resource kvSecretsOfficerRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name:  guid(kv.id, keyVaultAdminObjectId, keyVaultSecretsOfficerRoleId)
  scope: kv
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      keyVaultSecretsOfficerRoleId
    )
    principalId:   keyVaultAdminObjectId
    principalType: 'User'
  }
}

// ---------------------------------------------------------------------------
//  DCR Role Assignment — Monitoring Metrics Publisher
//  VM Managed Identity must have this to ingest data via DCR.
// ---------------------------------------------------------------------------

resource dcrRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name:  guid(dcr.id, vm.id, monitoringMetricsPublisherRoleId)
  scope: dcr
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      monitoringMetricsPublisherRoleId
    )
    principalId:   vm.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
//  NSG
//  Inbound: SSH from VirtualNetwork only (Bastion Developer SKU)
//           HTTPS/8080 from VirtualNetwork (NonProd AKS once peering is in place)
//  Deny-all explicit at end.
// ---------------------------------------------------------------------------

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name:     nsgName
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-SSH-Bastion'
        properties: {
          priority:                 100
          protocol:                 'Tcp'
          access:                   'Allow'
          direction:                'Inbound'
          sourceAddressPrefix:      'VirtualNetwork'
          sourcePortRange:          '*'
          destinationAddressPrefix: '*'
          destinationPortRange:     '22'
          description:              'SSH via Azure Bastion Developer SKU'
        }
      }
      {
        // Port 8080: LlamaFirewall proxy — NestJS AI Portal calls this
        // Currently unused until VNet peering with NonProduction AKS is in place.
        // Pre-provisioned so NSG is correct on day one of peering.
        name: 'Allow-LlamaFirewall-Proxy-VNet'
        properties: {
          priority:                 200
          protocol:                 'Tcp'
          access:                   'Allow'
          direction:                'Inbound'
          sourceAddressPrefix:      'VirtualNetwork'
          sourcePortRange:          '*'
          destinationAddressPrefix: '*'
          destinationPortRange:     '8080'
          description:              'LlamaFirewall proxy — NestJS AI Portal (VNet only)'
        }
      }
      {
        name: 'Deny-All-Inbound'
        properties: {
          priority:                 4000
          protocol:                 '*'
          access:                   'Deny'
          direction:                'Inbound'
          sourceAddressPrefix:      '*'
          sourcePortRange:          '*'
          destinationAddressPrefix: '*'
          destinationPortRange:     '*'
          description:              'Explicit deny-all'
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
//  VNet + Subnet
//  10.10.0.0/24 — chosen to avoid conflict with existing nonprod ranges:
//    vnet-aks-nprod-br  10.181.152.0/21
//    vnet-app-nprd-br   10.181.136.0/21
//    vnet-db-nprd-br    10.181.144.0/21
//  When networking team allocates a proper IPAM range, update this parameter.
// ---------------------------------------------------------------------------

resource vnet 'Microsoft.Network/virtualNetworks@2023-04-01' = {
  name:     vnetName
  location: location
  properties: {
    addressSpace: { addressPrefixes: ['10.10.0.0/24'] }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix:        '10.10.0.0/24'
          networkSecurityGroup: { id: nsg.id }
          // serviceEndpoints will be added when Key Vault is locked to VNet
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
//  NIC — no public IP (Bastion Developer SKU access)
// ---------------------------------------------------------------------------

resource nic 'Microsoft.Network/networkInterfaces@2023-04-01' = {
  name:     nicName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet:                    { id: '${vnet.id}/subnets/${subnetName}' }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
  }
  dependsOn: [vnet]
}

// ---------------------------------------------------------------------------
//  LlamaFirewall VM — Standard_NC8as_T4_v3
//  8 vCPU / 56GB RAM / 1× NVIDIA T4 16GB VRAM
//  System-Assigned Managed Identity for Key Vault + DCR access.
//  Trusted Launch DISABLED — required for NVIDIA GPU driver binding on Ubuntu.
// ---------------------------------------------------------------------------

resource vm 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name:     vmName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: 'Standard_NC8as_T4_v3' }
    securityProfile: {
      // Trusted Launch must be disabled for GPU VMs —
      // the NVIDIA kernel module cannot bind under vTPM/Secure Boot.
      securityType: 'Standard'
    }
    osProfile: {
      computerName:  vmName
      adminUsername: adminUsername
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path:    '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: adminPublicKey
            }
          ]
        }
        patchSettings: {
          patchMode:      'AutomaticByPlatform'
          assessmentMode: 'AutomaticByPlatform'
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer:     '0001-com-ubuntu-server-jammy'
        sku:       '22_04-lts-gen2'
        version:   'latest'
      }
      osDisk: {
        name:         diskName
        createOption: 'FromImage'
        managedDisk:  { storageAccountType: 'Premium_LRS' }
        diskSizeGB:   osDiskSizeGB
        deleteOption: 'Delete'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id:         nic.id
          properties: { deleteOption: 'Delete' }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: { enabled: false }
    }
  }
}

// ---------------------------------------------------------------------------
//  NVIDIA GPU Driver Extension
//  Installs the NVIDIA CUDA driver required for T4 GPU inference.
//  LlamaGuard3:8B and PromptGuard 2 run on GPU after this extension completes.
//  Extension completes in ~10 minutes post-VM provisioning.
//  VM requires a reboot after extension installs — setup_vm.sh handles this.
// ---------------------------------------------------------------------------

resource nvidiaExtension 'Microsoft.Compute/virtualMachines/extensions@2023-09-01' = {
  name:     'NvidiaGpuDriverLinux'
  parent:   vm
  location: location
  properties: {
    publisher:               'Microsoft.HpcCompute'
    type:                    'NvidiaGpuDriverLinux'
    typeHandlerVersion:      '1.9'
    autoUpgradeMinorVersion: true
    settings: {}
  }
}

// ---------------------------------------------------------------------------
//  Azure Bastion — Developer SKU (free tier)
//  Browser-based SSH access via Azure Portal. No public IP required.
//  Limitation: 1 concurrent session per Bastion instance.
//  Access: Portal → VM → Connect → Bastion
// ---------------------------------------------------------------------------

resource bastion 'Microsoft.Network/bastionHosts@2023-04-01' = {
  name:     bastionName
  location: location
  sku: { name: 'Developer' }
  properties: {
    virtualNetwork: { id: vnet.id }
  }
}

// ---------------------------------------------------------------------------
//  Auto-Shutdown — 23:00 UTC (20:00 BRT)
//  Prevents idle GPU VM costs overnight.
//  Disable this when the VM moves to production role.
// ---------------------------------------------------------------------------

resource autoShutdown 'Microsoft.DevTestLab/schedules@2018-09-15' = {
  name:     'shutdown-computevm-${vmName}'
  location: location
  properties: {
    status:               'Enabled'
    taskType:             'ComputeVmShutdownTask'
    dailyRecurrence:      { time: autoShutdownTime }
    timeZoneId:           'UTC'
    targetResourceId:     vm.id
    notificationSettings: { status: 'Disabled' }
  }
}

// ---------------------------------------------------------------------------
//  Outputs
// ---------------------------------------------------------------------------

@description('VM name.')
output vmName string = vm.name

@description('VM private IP — use this from the NonProd AKS (after VNet peering).')
output vmPrivateIP string = nic.properties.ipConfigurations[0].properties.privateIPAddress

@description('VM Managed Identity principal ID.')
output vmPrincipalId string = vm.identity.principalId

@description('Key Vault name — add secrets here after deployment.')
output keyVaultName string = kv.name

@description('Key Vault URI.')
output keyVaultUri string = kv.properties.vaultUri

@description('Log Analytics Workspace ID.')
output lawWorkspaceId string = law.properties.customerId

@description('Log Analytics resource ID.')
output lawResourceId string = law.id

@description('DCE ingestion endpoint — set as DCE_ENDPOINT in systemd service.')
output dceEndpoint string = dce.properties.logsIngestion.endpoint

@description('DCR immutable ID — set as DCR_IMMUTABLE_ID in systemd service.')
output dcrImmutableId string = dcr.properties.immutableId

@description('DCR stream name.')
output dcrStreamName string = 'Custom-LlamaFirewallPrompts_CL'

@description('Foundry endpoint configured for this deployment.')
output foundryEndpoint string = foundryEndpoint

@description('Foundry model deployment name.')
output foundryDeploymentName string = foundryDeploymentName

@description('VNet resource ID — provide this to the networking team for peering.')
output vnetResourceId string = vnet.id

@description('VNet address space — provide to networking team for IPAM verification.')
output vnetAddressSpace string = '10.10.0.0/24'
