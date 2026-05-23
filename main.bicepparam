// =============================================================================
//  LlamaFirewall / PyRIT — Parameters
//  Fill in adminPublicKey before deploying.
//  Set profile to match your target environment.
// =============================================================================

using './main.bicep'

// --- Required -----------------------------------------------------------------

// Paste the contents of ~/.ssh/id_ed25519.pub here.
// Generate one if needed:  ssh-keygen -t ed25519 -C "llamapoc"
param adminPublicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIANank1Xj0cdHHt7sBNBZM7Sso/gDWSofw5v23ObBpoE llamapoc'

// --- Environment profile ------------------------------------------------------
//
//  lab        → Standard_B8ms  (8 vCPU / 32 GB)  — phi3:mini    — 30d LAW — auto-shutdown
//  preprod    → Standard_D8s_v3 (8 vCPU / 32 GB) — mistral:7b   — 30d LAW — auto-shutdown
//  production → Standard_D16s_v3 (16 vCPU / 64 GB) — llama3:8b  — 90d LAW — no shutdown
//
param profile = 'lab'

// --- Optional overrides -------------------------------------------------------

param prefix   = 'llamapoc'

// eastus = cheapest; brazilsouth = lowest latency from São Paulo
param location = 'eastus'

// Auto-shutdown in UTC (lab + preprod only). São Paulo is UTC-3 (BRT).
// "2300" UTC = 20:00 BRT
param autoShutdownTime = '2300'

param adminUsername = 'azureuser'
param osDiskSizeGB  = 64
