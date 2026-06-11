// =============================================================================
//  LlamaFirewall / PyRIT — Parameters
//  Fill in adminPublicKey before deploying.
//  Set profile to match your target environment.
// =============================================================================

using './main.bicep'

// --- Required -----------------------------------------------------------------

// Paste the contents of ~/.ssh/id_ed25519.pub here.
// Check first: ls ~/.ssh/id_ed25519.pub
// If exists, use that key. If not: ssh-keygen -t ed25519 -C "llamapoc"
param adminPublicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIANank1Xj0cdHHt7sBNBZM7Sso/gDWSofw5v23ObBpoE llamapoc'

// --- Environment profile ------------------------------------------------------
//
//  lab        → Standard_B8ms          single VM  / laptop PyRIT  / SSH tunnel
//  preprod    → Standard_D8s_v3        single VM  / laptop PyRIT  / SSH tunnel
//  production → Standard_D16s_v3       single VM  / laptop PyRIT  / SSH tunnel
//  corp-lab   → NC4as_T4_v3 + B2ms     two VMs    / PyRIT VM      / BeyondTrust
//               ⚠️ Requires NC-series quota approval in sandbox subscription
//
param profile = 'lab'

// --- corp-lab only ------------------------------------------------------------
//
// BeyondTrust jump server IP/CIDR — restricts SSH access on both VMs.
// Replace with your actual BeyondTrust IP before deploying corp-lab.
// Example: '203.0.113.10/32'
// Leave as '*' only for initial testing — restrict before production sandbox use.
param beyondTrustSourceCIDR = '*'

// --- Optional overrides -------------------------------------------------------

param prefix   = 'llamapoc'

// eastus  = cheapest
// eastus2 = paired with East US, good redundancy
// brazilsouth = lowest latency from São Paulo
param location = 'eastus'

// Auto-shutdown in UTC (lab, preprod, corp-lab only)
// São Paulo is UTC-3 (BRT) — "2300" UTC = 20:00 BRT
param autoShutdownTime = '2300'

param adminUsername = 'azureuser'
param osDiskSizeGB  = 64
