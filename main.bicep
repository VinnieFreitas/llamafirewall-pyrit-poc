// =============================================================================
//  LlamaFirewall / PyRIT — Infrastructure
//  Resources: VNet, NSG, Public IP, NIC, Ubuntu VM, Log Analytics Workspace,
//             Auto-shutdown schedule (disabled for production profile)
//
//  Profiles:
//    lab        → B8ms  / 30-day LAW / auto-shutdown on  / phi3:mini
//    preprod    → D8s_v3 / 30-day LAW / auto-shutdown on  / mistral:7b
//    production → D16s_v3 / 90-day LAW / auto-shutdown off / llama3:8b
// =============================================================================

// ---------------------------------------------------------------------------
//  Parameters
// ---------------------------------------------------------------------------

@description('Environment profile — drives VM size, LAW retention, and auto-shutdown.')
@allowed(['lab', 'preprod', 'production'])
param profile string = 'lab'

@description('Short prefix applied to every resource name.')
@minLength(3)
@maxLength(10)
param prefix string = 'llamapoc'

@description('Azure region. brazilsouth for latency; eastus for lowest price.')
param location string = resourceGroup().location

@description('Admin username for the VM.')
param adminUsername string = 'azureuser'

@description('SSH public key (contents of ~/.ssh/id_ed25519.pub or similar).')
param adminPublicKey string

@description('OS disk size in GB.')
param osDiskSizeGB int = 64

@description('Daily auto-shutdown time in UTC (HHmm). Only applies to lab and preprod profiles.')
param autoShutdownTime string = '2300'

// ---------------------------------------------------------------------------
//  Profile configuration
//  All environment-specific values derived from the profile parameter.
// ---------------------------------------------------------------------------

var profileConfig = {
  lab: {
    vmSize:          'Standard_B8ms'      // 8 vCPU / 32 GB — burstable, cost-optimised
    lawRetention:    30                   // minimum retention
    autoShutdown:    true                 // deallocate nightly
    diskType:        'StandardSSD_LRS'
    description:     'Lab — burstable B-series, phi3:mini, aggressive scanning thresholds'
  }
  preprod: {
    vmSize:          'Standard_D8s_v3'   // 8 vCPU / 32 GB — sustained CPU, non-burstable
    lawRetention:    30
    autoShutdown:    true
    diskType:        'Premium_LRS'        // faster disk for mistral:7b model loads
    description:     'Pre-Production — D-series sustained CPU, mistral:7b, balanced thresholds'
  }
  production: {
    vmSize:          'Standard_D16s_v3'  // 16 vCPU / 64 GB — room for all scanners + output scan
    lawRetention:    90
    autoShutdown:    false               // never auto-shutdown in production
    diskType:        'Premium_LRS'
    description:     'Production — D-series high CPU, llama3:8b, conservative thresholds'
  }
}

var cfg        = profileConfig[profile]
var vmName     = '${prefix}-vm'
var lawName    = '${prefix}-law'
var vnetName   = '${prefix}-vnet'
var subnetName = 'default'
var nsgName    = '${prefix}-nsg'
var pipName    = '${prefix}-pip'
var nicName    = '${prefix}-nic'
var osDiskName = '${prefix}-osdisk'
var dnsLabel   = '${prefix}-llama'

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
      disableLocalAuth:                          false
      enableLogAccessUsingOnlyResourcePermissions: false
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery:     'Enabled'
  }
}

// ---------------------------------------------------------------------------
//  NSG — SSH only inbound
// ---------------------------------------------------------------------------

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name:     nsgName
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
          // Restrict to your home IP for better security:
          //   sourceAddressPrefix: '203.0.113.42/32'
          sourceAddressPrefix:      '*'
          sourcePortRange:          '*'
          destinationAddressPrefix: '*'
          destinationPortRange:     '22'
          description: 'SSH for admin access and PyRIT tunnel'
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
          description: 'Explicit deny-all'
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
//  VNet + Subnet
// ---------------------------------------------------------------------------

resource vnet 'Microsoft.Network/virtualNetworks@2023-04-01' = {
  name:     vnetName
  location: location
  properties: {
    addressSpace: { addressPrefixes: ['10.0.0.0/16'] }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix:          '10.0.0.0/24'
          networkSecurityGroup: { id: nsg.id }
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
//  Public IP
// ---------------------------------------------------------------------------

resource pip 'Microsoft.Network/publicIPAddresses@2023-04-01' = {
  name:     pipName
  location: location
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
    dnsSettings: { domainNameLabel: dnsLabel }
  }
}

// ---------------------------------------------------------------------------
//  NIC
// ---------------------------------------------------------------------------

resource nic 'Microsoft.Network/networkInterfaces@2023-04-01' = {
  name:     nicName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet:                    { id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, subnetName) }
          publicIPAddress:           { id: pip.id }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
  }
  dependsOn: [vnet]
}

// ---------------------------------------------------------------------------
//  Virtual Machine
// ---------------------------------------------------------------------------

resource vm 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name:     vmName
  location: location
  properties: {
    hardwareProfile: { vmSize: cfg.vmSize }
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
        name:         osDiskName
        createOption: 'FromImage'
        managedDisk:  { storageAccountType: cfg.diskType }
        diskSizeGB:   osDiskSizeGB
        deleteOption: 'Delete'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
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
//  Auto-Shutdown — only for lab and preprod profiles
// ---------------------------------------------------------------------------

resource autoShutdown 'Microsoft.DevTestLab/schedules@2018-09-15' = if (cfg.autoShutdown) {
  name:     'shutdown-computevm-${vmName}'
  location: location
  properties: {
    status:   'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: { time: autoShutdownTime }
    timeZoneId: 'UTC'
    targetResourceId: vm.id
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

@description('VM size used.')
output vmSizeUsed string = cfg.vmSize

@description('VM public IP address.')
output vmPublicIP string = pip.properties.ipAddress

@description('VM FQDN.')
output vmFQDN string = pip.properties.dnsSettings.fqdn

@description('SSH command.')
output sshCommand string = 'ssh ${adminUsername}@${pip.properties.dnsSettings.fqdn}'

@description('SSH tunnel command.')
output sshTunnelCommand string = 'ssh -N -L 8080:localhost:8080 ${adminUsername}@${pip.properties.dnsSettings.fqdn}'

@description('Log Analytics Workspace ID.')
output lawWorkspaceId string = law.properties.customerId

@description('Log Analytics resource ID.')
output lawResourceId string = law.id
