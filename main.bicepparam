// =============================================================================
//  LlamaFirewall / PyRIT PoC — Parameters
//  Fill in adminPublicKey before deploying. Everything else has sensible
//  defaults, but read the comments — a few values are worth customising.
// =============================================================================

using './main.bicep'

// --- Required -----------------------------------------------------------------

// Paste the contents of ~/.ssh/id_rsa.pub (or id_ed25519.pub) here.
// Generate one if you don't have it:  ssh-keygen -t ed25519 -C "llamapoc"
param adminPublicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIANank1Xj0cdHHt7sBNBZM7Sso/gDWSofw5v23ObBpoE llamapoc'

// --- Recommended to customise -------------------------------------------------

// Short prefix — keep it lowercase alphanumeric, 3–10 chars.
param prefix = 'llamapoc'

// Region options (pick one and delete the others):
//   'brazilsouth'  — lowest latency from São Paulo, slightly higher VM price
//   'eastus'       — cheapest VMs globally, ~150 ms latency from SP
//   'eastus2'      — same price as eastus, sometimes better availability
param location = 'eastus'

// Auto-shutdown in UTC. Adjust to your timezone:
//   São Paulo is UTC-3 (BRT) / UTC-2 (BRST in summer)
//   "2300" UTC = 20:00 BRT / 21:00 BRST
param autoShutdownTime = '2300'

// --- Optional overrides -------------------------------------------------------

param adminUsername = 'azureuser'

// Standard_B4ms = 4 vCPU / 16 GB — recommended
// Standard_B2ms = 2 vCPU /  8 GB — only if very cost-constrained
param vmSize = 'Standard_B4ms'

param osDiskSizeGB = 64

// 30 days = minimum retention = minimum Log Analytics cost
param lawRetentionDays = 30
