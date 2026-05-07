// =============================================================================
//  LlamaFirewall / PyRIT PoC — Infrastructure
//  Resources: VNet, NSG, Public IP, NIC, Ubuntu VM, Log Analytics Workspace,
//             Auto-shutdown schedule
// =============================================================================

// ---------------------------------------------------------------------------
//  Parameters
// ---------------------------------------------------------------------------

@description('Short prefix applied to every resource name.')
@minLength(3)
@maxLength(10)
param prefix string = 'llamapoc'

@description('Azure region. brazilsouth for latency; eastus for lowest price.')
param location string = resourceGroup().location

@description('Admin username for the VM.')
param adminUsername string = 'azureuser'

@description('SSH public key (contents of ~/.ssh/id_rsa.pub or similar).')
param adminPublicKey string

@description('''
VM size.
  Standard_B4ms  → 4 vCPU / 16 GB RAM  — recommended (Ollama + LlamaFirewall)
  Standard_B2ms  → 2 vCPU /  8 GB RAM  — workable for Phi-3-mini only
''')
@allowed([
  'Standard_B2ms'
  'Standard_B4ms'
  'Standard_B8ms'
])
param vmSize string = 'Standard_B4ms'

@description('OS disk size in GB. 64 GB is enough for Ubuntu + Ollama + one model.')
param osDiskSizeGB int = 64

@description('''
Daily auto-shutdown time in UTC using HHmm format (e.g. "2300" = 11 PM UTC).
Adjust to match your timezone. This is the single best cost-saving lever.
''')
param autoShutdownTime string = '2300'

@description('Log Analytics retention in days. 30 is the minimum (and cheapest).')
@minValue(30)
@maxValue(730)
param lawRetentionDays int = 30

// ---------------------------------------------------------------------------
//  Variables
// ---------------------------------------------------------------------------

var vmName       = '${prefix}-vm'
var lawName      = '${prefix}-law'
var vnetName     = '${prefix}-vnet'
var subnetName   = 'default'
var nsgName      = '${prefix}-nsg'
var pipName      = '${prefix}-pip'
var nicName      = '${prefix}-nic'
var osDiskName   = '${prefix}-osdisk'
var dnsLabel     = '${prefix}-llama'   // results in <dnsLabel>.<region>.cloudapp.azure.com

// ---------------------------------------------------------------------------
//  Log Analytics Workspace
//  PerGB2018 = pay-per-GB. First 5 GB/month are free.
//  30-day retention = minimum cost.
// ---------------------------------------------------------------------------

resource law 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: lawName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: lawRetentionDays
    features: {
      // Keep local auth enabled — needed for the custom log shipper in step 4.
      disableLocalAuth: false
      enableLogAccessUsingOnlyResourcePermissions: false
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// ---------------------------------------------------------------------------
//  Network Security Group
//  ONLY port 22 (SSH) is open inbound. LlamaFirewall (8080) is intentionally
//  NOT exposed — PyRIT reaches it through an SSH tunnel (see outputs below).
// ---------------------------------------------------------------------------

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: nsgName
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-SSH-Inbound'
        properties: {
          priority:                   100
          protocol:                   'Tcp'
          access:                     'Allow'
          direction:                  'Inbound'
          // ⚠️  Restrict this to your home IP for better security:
          //     sourceAddressPrefix: '203.0.113.42/32'
          sourceAddressPrefix:        '*'
          sourcePortRange:            '*'
          destinationAddressPrefix:   '*'
          destinationPortRange:       '22'
          description: 'SSH for admin access and PyRIT tunnel'
        }
      }
      {
        name: 'Deny-All-Inbound'
        properties: {
          priority:                   4000
          protocol:                   '*'
          access:                     'Deny'
          direction:                  'Inbound'
          sourceAddressPrefix:        '*'
          sourcePortRange:            '*'
          destinationAddressPrefix:   '*'
          destinationPortRange:       '*'
          description: 'Explicit deny-all — defence in depth'
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
//  Virtual Network + Subnet
// ---------------------------------------------------------------------------

resource vnet 'Microsoft.Network/virtualNetworks@2023-04-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.0.0.0/16']
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: '10.0.0.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
//  Public IP  (Standard SKU = required for Static allocation)
// ---------------------------------------------------------------------------

resource pip 'Microsoft.Network/publicIPAddresses@2023-04-01' = {
  name: pipName
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    dnsSettings: {
      domainNameLabel: dnsLabel
    }
  }
}

// ---------------------------------------------------------------------------
//  Network Interface
// ---------------------------------------------------------------------------

resource nic 'Microsoft.Network/networkInterfaces@2023-04-01' = {
  name: nicName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, subnetName)
          }
          publicIPAddress: {
            id: pip.id
          }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
  }
  dependsOn: [vnet]
}

// ---------------------------------------------------------------------------
//  Virtual Machine
//  Ubuntu 22.04 LTS Gen2 — stable, well-supported by Ollama and Python 3.
//  SSH-key auth only. Boot diagnostics disabled (saves a storage account).
// ---------------------------------------------------------------------------

resource vm 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: vmName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: vmSize
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
        // Automatic OS security patches — keep this on for a personal lab.
        patchSettings: {
          patchMode:            'AutomaticByPlatform'
          assessmentMode:       'AutomaticByPlatform'
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
        managedDisk: {
          // StandardSSD_LRS: good balance of cost vs. model-load performance.
          // Switch to Premium_LRS if you need faster disk I/O.
          storageAccountType: 'StandardSSD_LRS'
        }
        diskSizeGB: osDiskSizeGB
        deleteOption: 'Delete'    // Disk is removed when VM is deleted — avoids orphan cost.
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            deleteOption: 'Delete'  // NIC removed with VM.
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: false  // Disabled — avoids provisioning a storage account.
      }
    }
  }
}

// ---------------------------------------------------------------------------
//  Auto-Shutdown Schedule
//  This is the #1 cost-saving measure. The VM deallocates at autoShutdownTime
//  every day. You start it manually when you need a test session.
// ---------------------------------------------------------------------------

resource autoShutdown 'Microsoft.DevTestLab/schedules@2018-09-15' = {
  // Name format is fixed — Azure requires this exact pattern.
  name:     'shutdown-computevm-${vmName}'
  location: location
  properties: {
    status:   'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: {
      time: autoShutdownTime
    }
    timeZoneId: 'UTC'
    targetResourceId: vm.id
    notificationSettings: {
      status: 'Disabled'
    }
  }
}

// ---------------------------------------------------------------------------
//  Outputs
//  Copy these after deployment — you'll need them in later steps.
// ---------------------------------------------------------------------------

@description('VM public IP address.')
output vmPublicIP string = pip.properties.ipAddress

@description('VM fully-qualified domain name.')
output vmFQDN string = pip.properties.dnsSettings.fqdn

@description('SSH command to connect to the VM.')
output sshCommand string = 'ssh ${adminUsername}@${pip.properties.dnsSettings.fqdn}'

@description('SSH tunnel command — exposes LlamaFirewall port 8080 on localhost.')
output sshTunnelCommand string = 'ssh -N -L 8080:localhost:8080 ${adminUsername}@${pip.properties.dnsSettings.fqdn}'

@description('Log Analytics Workspace ID (used by the log shipper in step 4).')
output lawWorkspaceId string = law.properties.customerId

@description('Log Analytics resource ID (used when attaching Sentinel later).')
output lawResourceId string = law.id
