// =============================================================================
//  LlamaFirewall / PyRIT — Infrastructure
//
//  Profiles:
//    lab        → single VM B8ms        / home use  / SSH tunnel from laptop
//    preprod    → single VM D8s_v3      / home use  / SSH tunnel from laptop
//    production → single VM D16s_v3     / home use  / SSH tunnel from laptop
//    corp-lab   → two VMs (PyRIT B2ms + LlamaFirewall NC4as_T4_v3)
//                 sandbox subscription  / Azure Bastion Developer SKU / no SSH tunnel
//
//  ⚠️  corp-lab uses Standard_NC4as_T4_v3 (GPU).
//      This VM size requires quota approval in your subscription before deploying.
//      Request quota at: Portal → Subscriptions → Usage + quotas → Request increase
// =============================================================================

// ---------------------------------------------------------------------------
//  Parameters
// ---------------------------------------------------------------------------

@description('Environment profile.')
@allowed(['lab', 'preprod', 'production', 'corp-lab'])
param profile string = 'lab'

@description('Short prefix applied to every resource name.')
@minLength(3)
@maxLength(10)
param prefix string = 'llamapoc'

@description('Azure region.')
param location string = resourceGroup().location

@description('Admin username for both VMs.')
param adminUsername string = 'azureuser'

@description('SSH public key.')
param adminPublicKey string

@description('OS disk size in GB.')
param osDiskSizeGB int = 64

@description('Daily auto-shutdown time in UTC (HHmm). Applies to lab, preprod and corp-lab profiles.')
param autoShutdownTime string = '2300'

@description('''
Azure Bastion Developer SKU is used for SSH access to corp profile VMs.
No CIDR parameter needed — Bastion Developer connects via Azure internal networking.
The NSG allows SSH from the VirtualNetwork service tag only.
Bastion Developer SKU is free and deployed automatically for corp profiles.
''')

// ---------------------------------------------------------------------------
//  Profile configuration
// ---------------------------------------------------------------------------

var profileConfig = {
  lab: {
    llamafirewallVMSize: 'Standard_B8ms'
    pyritVMSize:         ''                  // no PyRIT VM — runs on laptop
    lawRetention:        30
    autoShutdown:        true
    diskType:            'StandardSSD_LRS'
    deployPyRITVM:       false
    publicIP:            true                // needs public IP for SSH tunnel from laptop
    description:         'Home Lab — B8ms, phi3:mini, SSH tunnel from laptop'
  }
  preprod: {
    llamafirewallVMSize: 'Standard_D8s_v3'
    pyritVMSize:         ''
    lawRetention:        30
    autoShutdown:        true
    diskType:            'Premium_LRS'
    deployPyRITVM:       false
    publicIP:            false               // corporate — Azure Bastion Developer SKU access
    description:         'Corp Pre-prod — D8s_v3, mistral:7b, Azure Bastion access'
  }
  production: {
    llamafirewallVMSize: 'Standard_D16s_v3'
    pyritVMSize:         ''
    lawRetention:        90
    autoShutdown:        false
    diskType:            'Premium_LRS'
    deployPyRITVM:       false
    publicIP:            false               // corporate — Azure Bastion Developer SKU access
    description:         'Corp Production — D16s_v3, llama3:8b, Azure Bastion access'
  }
  'corp-lab': {
    llamafirewallVMSize: 'Standard_NC4as_T4_v3'  // GPU — requires quota approval
    pyritVMSize:         'Standard_B2ms'
    lawRetention:        30
    autoShutdown:        true
    diskType:            'Premium_LRS'
    deployPyRITVM:       true                     // deploys a second VM for PyRIT
    publicIP:            false                    // no public IP — Azure Bastion Developer SKU access
    description:         'Corp Lab — NC4as T4 GPU + PyRIT VM, Azure Bastion access, sandbox VNet'
  }
}

var cfg = profileConfig[profile]

// Whether this profile uses Managed Identity for LAW ingestion
// lab / corp-lab: Shared Key (simpler, fine for sandbox)
// preprod / production: Managed Identity + DCR (zero-trust, no static keys)
var useManagedIdentity = (profile == 'preprod' || profile == 'production')

// Resource names — LlamaFirewall VM
var lfVMName    = '${prefix}-lf-vm'
var lfNICName   = '${prefix}-lf-nic'
var lfPIPName   = '${prefix}-lf-pip'
var lfDiskName  = '${prefix}-lf-osdisk'
var lfDNSLabel  = '${prefix}-llama'

// Resource names — PyRIT VM (corp-lab only)
var pyritVMName   = '${prefix}-pyrit-vm'
var pyritNICName  = '${prefix}-pyrit-nic'
var pyritPIPName  = '${prefix}-pyrit-pip'
var pyritDNSLabel = '${prefix}-pyrit'

// Shared resources
var lawName    = '${prefix}-law'
var dceName    = '${prefix}-dce'
var dcrName    = '${prefix}-dcr-prompts'
var vnetName   = '${prefix}-vnet'
var lfNSGName  = '${prefix}-lf-nsg'
var pyritNSGName = '${prefix}-pyrit-nsg'

// Subnets
var lfSubnetName    = 'llamafirewall-subnet'
var pyritSubnetName = 'pyrit-subnet'

// Built-in role: Monitoring Metrics Publisher
// Required for Managed Identity to ingest data via DCR
var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'

// ---------------------------------------------------------------------------
//  Log Analytics Workspace
// ---------------------------------------------------------------------------

resource law 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name:     lawName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: cfg.lawRetention
    features: {
      disableLocalAuth:                            false
      enableLogAccessUsingOnlyResourcePermissions: false
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery:     'Enabled'
  }
}

// ---------------------------------------------------------------------------
//  Data Collection Endpoint (DCE) — preprod/production only
//  Required for DCR-based log ingestion via Managed Identity.
//  Provides the ingestion URL that proxy.py posts to.
// ---------------------------------------------------------------------------

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' = if (useManagedIdentity) {
  name:     dceName
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// ---------------------------------------------------------------------------
//  Data Collection Rule (DCR) — preprod/production only
//  Defines the stream → LAW table mapping for LlamaFirewallPrompts_CL.
//  The VM's Managed Identity must have Monitoring Metrics Publisher on this DCR.
// ---------------------------------------------------------------------------

resource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' = if (useManagedIdentity) {
  name:     dcrName
  location: location
  properties: {
    dataCollectionEndpointId: useManagedIdentity ? dce.id : null
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
//  Role assignment — Monitoring Metrics Publisher on DCR
//  Grants the LlamaFirewall VM's System-Assigned Managed Identity permission
//  to ingest data through the DCR.
// ---------------------------------------------------------------------------

resource dcrRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (useManagedIdentity) {
  name:  guid(dcr.id, lfVM.id, monitoringMetricsPublisherRoleId)
  scope: dcr
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      monitoringMetricsPublisherRoleId
    )
    principalId:   lfVM.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
//  NSG — LlamaFirewall VM
//  home profiles: SSH from any (restrict to home IP for better security)
//  All corp profiles: SSH from VirtualNetwork service tag only
//  (Azure Bastion Developer SKU connects via Azure internal networking —
//   no public IP or specific CIDR required)
//  home-lab: SSH from any IP (restrict sourceAddressPrefix for production use)
// ---------------------------------------------------------------------------

resource lfNSG 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name:     lfNSGName
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-SSH-Inbound'
        properties: {
          priority:                 100
          protocol:                 'Tcp'
          access:                   'Allow'
          direction:                'Inbound'
          sourceAddressPrefix:      profile == 'lab' ? '*' : 'VirtualNetwork'
          sourcePortRange:          '*'
          destinationAddressPrefix: '*'
          destinationPortRange:     '22'
          description: profile == 'lab'
            ? 'SSH for admin access and PyRIT tunnel'
            : 'SSH via Azure Bastion Developer SKU (VirtualNetwork service tag)'
        }
      }
      // corp-lab only: allow PyRIT VM to reach LlamaFirewall on port 8080
      ...(profile == 'corp-lab' ? [
        {
          name: 'Allow-PyRIT-to-LlamaFirewall'
          properties: {
            priority:                 200
            protocol:                 'Tcp'
            access:                   'Allow'
            direction:                'Inbound'
            sourceAddressPrefix:      '10.0.1.0/24'   // PyRIT subnet
            sourcePortRange:          '*'
            destinationAddressPrefix: '*'
            destinationPortRange:     '8080'
            description:              'PyRIT VM → LlamaFirewall proxy (internal VNet only)'
          }
        }
      ] : [])
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
//  PyRIT VM NSG (corp-lab only)
//  SSH from VirtualNetwork service tag (Azure Bastion Developer SKU).
//  Outbound to LlamaFirewall on 8080 is handled by the LF NSG allow rule.
// ---------------------------------------------------------------------------

resource pyritNSG 'Microsoft.Network/networkSecurityGroups@2023-04-01' = if (cfg.deployPyRITVM) {
  name:     pyritNSGName
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
          description:              'SSH via Azure Bastion Developer SKU (VirtualNetwork service tag)'
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
//  VNet + Subnets
//  home profiles: single subnet (default)
//  corp-lab:      two subnets — one per VM
// ---------------------------------------------------------------------------

resource vnet 'Microsoft.Network/virtualNetworks@2023-04-01' = {
  name:     vnetName
  location: location
  properties: {
    addressSpace: { addressPrefixes: ['10.0.0.0/16'] }
    subnets: profile == 'corp-lab' ? [
      {
        name: lfSubnetName
        properties: {
          addressPrefix:          '10.0.0.0/24'
          networkSecurityGroup: { id: lfNSG.id }
        }
      }
      {
        name: pyritSubnetName
        properties: {
          addressPrefix:          '10.0.1.0/24'
          networkSecurityGroup: { id: pyritNSG.id }
        }
      }
    ] : [
      {
        name: 'default'
        properties: {
          addressPrefix:          '10.0.0.0/24'
          networkSecurityGroup: { id: lfNSG.id }
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
//  Public IPs
// ---------------------------------------------------------------------------

resource lfPIP 'Microsoft.Network/publicIPAddresses@2023-04-01' = if (cfg.publicIP) {
  name:     lfPIPName
  location: location
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
    dnsSettings: { domainNameLabel: lfDNSLabel }
  }
}

resource pyritPIP 'Microsoft.Network/publicIPAddresses@2023-04-01' = if (cfg.deployPyRITVM && cfg.publicIP) {
  name:     pyritPIPName
  location: location
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
    dnsSettings: { domainNameLabel: pyritDNSLabel }
  }
}

// ---------------------------------------------------------------------------
//  NICs
// ---------------------------------------------------------------------------

resource lfNIC 'Microsoft.Network/networkInterfaces@2023-04-01' = {
  name:     lfNICName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName,
              profile == 'corp-lab' ? lfSubnetName : 'default')
          }
          publicIPAddress: cfg.publicIP ? { id: lfPIP.id } : null
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
  }
  dependsOn: [vnet]
}

resource pyritNIC 'Microsoft.Network/networkInterfaces@2023-04-01' = if (cfg.deployPyRITVM) {
  name:     pyritNICName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, pyritSubnetName)
          }
          publicIPAddress: cfg.publicIP ? { id: pyritPIP.id } : null
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
  }
  dependsOn: [vnet]
}

// ---------------------------------------------------------------------------
//  LlamaFirewall VM
// ---------------------------------------------------------------------------

resource lfVM 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name:     lfVMName
  location: location
  // System-Assigned Managed Identity — preprod/production only
  // Used for DCR-based LAW ingestion (no static keys stored anywhere)
  identity: useManagedIdentity ? { type: 'SystemAssigned' } : null
  properties: {
    hardwareProfile: { vmSize: cfg.llamafirewallVMSize }
    // ---------------------------------------------------------------------------
    //  Security profile — Trusted Launch must be DISABLED for GPU VMs.
    //  corp profiles (corp-lab, preprod, production) use Standard security type
    //  so the NVIDIA driver kernel module can bind correctly.
    //  home-lab keeps TrustedLaunch (no GPU, more secure default).
    // ---------------------------------------------------------------------------
    securityProfile: {
      securityType: (profile == 'lab') ? 'TrustedLaunch' : 'Standard'
      uefiSettings: (profile == 'lab') ? {
        secureBootEnabled: true
        vTpmEnabled:       true
      } : null
    }
    osProfile: {
      computerName:  lfVMName
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
        name:         lfDiskName
        createOption: 'FromImage'
        managedDisk:  { storageAccountType: cfg.diskType }
        diskSizeGB:   osDiskSizeGB
        deleteOption: 'Delete'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: lfNIC.id
          properties: { deleteOption: 'Delete' }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: { enabled: false }
    }
  }
}

// NVIDIA GPU driver extension — corp-lab only (NC-series requires manual driver install on Ubuntu)
resource nvidiaExtension 'Microsoft.Compute/virtualMachines/extensions@2023-09-01' = if (profile == 'corp-lab') {
  name:     'NvidiaGpuDriverLinux'
  parent:   lfVM
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
//  PyRIT VM (corp-lab only)
// ---------------------------------------------------------------------------

resource pyritVM 'Microsoft.Compute/virtualMachines@2023-09-01' = if (cfg.deployPyRITVM) {
  name:     pyritVMName
  location: location
  properties: {
    hardwareProfile: { vmSize: cfg.pyritVMSize }
    securityProfile: {
      securityType: 'Standard'   // Trusted Launch disabled — consistent with LF VM in corp profiles
    }
    osProfile: {
      computerName:  pyritVMName
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
        name:         '${prefix}-pyrit-osdisk'
        createOption: 'FromImage'
        managedDisk:  { storageAccountType: 'StandardSSD_LRS' }
        diskSizeGB:   32
        deleteOption: 'Delete'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: pyritNIC.id
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
//  Azure Bastion — Developer SKU (corp profiles only)
//  Free tier. Provides browser-based SSH access via Azure Portal.
//  No dedicated AzureBastionSubnet or public IP required.
//  Limitation: 1 concurrent session per Bastion instance.
//  Access: Portal → <VM> → Connect → Bastion
// ---------------------------------------------------------------------------

resource bastion 'Microsoft.Network/bastionHosts@2023-04-01' = if (!cfg.publicIP) {
  name:     '${prefix}-bastion'
  location: location
  sku: {
    name: 'Developer'
  }
  properties: {
    virtualNetwork: {
      id: vnet.id
    }
  }
}

// ---------------------------------------------------------------------------
//  Auto-Shutdown
// ---------------------------------------------------------------------------

resource lfAutoShutdown 'Microsoft.DevTestLab/schedules@2018-09-15' = if (cfg.autoShutdown) {
  name:     'shutdown-computevm-${lfVMName}'
  location: location
  properties: {
    status:                  'Enabled'
    taskType:                'ComputeVmShutdownTask'
    dailyRecurrence:         { time: autoShutdownTime }
    timeZoneId:              'UTC'
    targetResourceId:        lfVM.id
    notificationSettings:    { status: 'Disabled' }
  }
}

resource pyritAutoShutdown 'Microsoft.DevTestLab/schedules@2018-09-15' = if (cfg.autoShutdown && cfg.deployPyRITVM) {
  name:     'shutdown-computevm-${pyritVMName}'
  location: location
  properties: {
    status:               'Enabled'
    taskType:             'ComputeVmShutdownTask'
    dailyRecurrence:      { time: autoShutdownTime }
    timeZoneId:           'UTC'
    targetResourceId:     pyritVM.id
    notificationSettings: { status: 'Disabled' }
  }
}

// ---------------------------------------------------------------------------
//  Outputs
// ---------------------------------------------------------------------------

@description('Active environment profile.')
output activeProfile string = profile

@description('Profile description.')
output profileDescription string = cfg.description

@description('LlamaFirewall VM size.')
output vmSizeUsed string = cfg.llamafirewallVMSize

@description('LlamaFirewall VM public IP.')
output vmPublicIP string = cfg.publicIP ? lfPIP.properties.ipAddress : 'no-public-ip'

@description('LlamaFirewall VM FQDN.')
output vmFQDN string = cfg.publicIP ? lfPIP.properties.dnsSettings.fqdn : 'no-public-ip'

@description('SSH connect command — LlamaFirewall VM.')
output sshCommand string = 'ssh ${adminUsername}@${cfg.publicIP ? (lfPIP.properties.dnsSettings.fqdn ?? 'no-public-ip') : 'no-public-ip'}'

@description('SSH tunnel command (home profiles only).')
output sshTunnelCommand string = 'ssh -N -L 8080:localhost:8080 ${adminUsername}@${cfg.publicIP ? (lfPIP.properties.dnsSettings.fqdn ?? 'no-public-ip') : 'no-public-ip'}'

@description('PyRIT VM public IP (corp-lab only).')
output pyritVMPublicIP string = (cfg.deployPyRITVM && cfg.publicIP) ? (pyritPIP.properties.ipAddress ?? 'n/a') : 'n/a'

@description('PyRIT VM FQDN (corp-lab only).')
output pyritVMFQDN string = (cfg.deployPyRITVM && cfg.publicIP) ? (pyritPIP.properties.dnsSettings.fqdn ?? 'n/a') : 'n/a'

@description('SSH connect command — PyRIT VM (corp-lab only).')
output pyritSSHCommand string = (cfg.deployPyRITVM && cfg.publicIP) ? 'ssh ${adminUsername}@${pyritPIP.properties.dnsSettings.fqdn ?? 'n/a'}' : 'n/a'

@description('LlamaFirewall VM private IP — use this from the PyRIT VM (corp-lab).')
output llamafirewallPrivateIP string = lfNIC.properties.ipConfigurations[0].properties.privateIPAddress

@description('Log Analytics Workspace ID.')
output lawWorkspaceId string = law.properties.customerId

@description('Log Analytics resource ID.')
output lawResourceId string = law.id

@description('Ingestion method — shared_key (lab/corp-lab) or managed_identity (preprod/production).')
output lawIngestionMethod string = useManagedIdentity ? 'managed_identity' : 'shared_key'

@description('DCE ingestion endpoint (preprod/production only).')
output dceEndpoint string = useManagedIdentity ? dce.properties.logsIngestion.endpoint : 'n/a'

@description('DCR immutable ID (preprod/production only).')
output dcrImmutableId string = useManagedIdentity ? dcr.properties.immutableId : 'n/a'

@description('DCR stream name for LlamaFirewallPrompts_CL.')
output dcrStreamName string = useManagedIdentity ? 'Custom-LlamaFirewallPrompts_CL' : 'n/a'

@description('LlamaFirewall VM Managed Identity principal ID (preprod/production only).')
output lfVMManagedIdentityPrincipalId string = useManagedIdentity ? lfVM.identity.principalId : 'n/a'
