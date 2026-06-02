# LlamaFirewall + PyRIT — AI Security Pipeline

A layered LLM security pipeline built on Azure, with automated red-team testing
and observability via Log Analytics and Azure Workbook. Deployable across four
environment profiles — from a personal home lab to a corporate AKS production
deployment.

---

## Architecture

The project supports four deployment profiles, each with a different topology:

**home-lab / home-preprod / home-production** — single VM, laptop runs PyRIT:
```
[ Linux Laptop ]                          [ Azure VM ]
  PyRIT ─── SSH tunnel ──────────────►  LlamaFirewall proxy (:8080)
  log_shipper ──────────────────────►          │
                                          Ollama + LLM (:11434)
                                               │
                                    Log Analytics Workspace
                                               │
                                    Azure Workbook Dashboard
```

**corp-lab** — two VMs in sandbox subscription, BeyondTrust access:
```
[ BeyondTrust ]
      │ SSH
      ├──► PyRIT VM (B2ms)  ──────────────► LlamaFirewall VM (NC4as T4 GPU)
      └──► LlamaFirewall VM                         │
                                            Log Analytics → Sentinel
```

**corp-preprod / corp-prod** — LlamaFirewall containerised inside AKS:
```
User → EntraID → Angular SPA (AKS)
                      │
                 Backend (AKS)
                      │  OPENAI_ENDPOINT=http://llamafirewall-svc:8080/v1
                      ▼
              LlamaFirewall pod (AKS)   ← one env var change in backend
                      │
                 Azure OpenAI (private endpoint, different subscription)
                      │
              Sentinel LAW ← canary CronJob (hourly)
```

---

## Stack

- **Ollama** — local LLM inference server. Exposes an OpenAI-compatible API on `:11434`. Used in home profiles in place of Azure OpenAI — swap one URL for production.
- **LLM model** — `phi3:mini` (lab) / `mistral:7b` (preprod) / `llama3:8b` (production)
- **LlamaFirewall** — Meta's open-source LLM security framework, extended with a 6-layer scanner stack
- **PyRIT** — Microsoft's open-source AI red-teaming toolkit
- **NOVA** — YARA-style prompt pattern matching engine (novahunting.ai)
- **Observability** — Azure Log Analytics → Azure Workbook → Microsoft Sentinel

**LlamaFirewall stack — 6 layers, runs in order on every prompt:**

| Layer | Scanner | Type | Catches |
|---|---|---|---|
| 1 | PromptGuard 2 | ML classifier | Injection syntax, jailbreaks |
| 2 | HiddenASCII | Rule-based | BiDi text, invisible chars, encoding tricks |
| 3 | Regex + CustomPatterns | Rule-based | XSS, SQL injection, credentials, tool abuse |
| 4 | LlamaGuard 3:8B | Semantic LLM | Social engineering, content safety, subtle jailbreaks |
| 5 | NOVA (keyword+semantic) | YARA-style rules | Logic traps, tool injection, bioweapon synthesis, political manipulation |
| 6 | Output scan *(preprod/prod)* | LlamaGuard 3:8B | Harmful content in LLM responses |

**Achieved: 98.85% detection on 87-prompt adversarial dataset (+55.17% from single-scanner baseline)**

---

## Environment Profiles

Four profiles drive VM size, LLM model, scanner thresholds, and topology.
Both `deploy.sh` and `setup_vm.sh` prompt you to select a profile interactively.

| Setting | home-lab | corp-lab | preprod | production |
|---|---|---|---|---|
| **Topology** | Single VM | Two VMs | Single VM | Single VM |
| **LF VM size** | B8ms | NC4as_T4_v3 (GPU) | D8s_v3 | D16s_v3 |
| **PyRIT** | Laptop | B2ms VM | Laptop/CI | Canary probe |
| **LLM model** | phi3:mini | phi3:mini | mistral:7b | llama3:8b |
| **PromptGuard threshold** | 0.05 | 0.05 | 0.10 | 0.15 |
| **Output scanning** | ❌ | ❌ | ✅ | ✅ |
| **NOVA LLM tier** | ❌ | ❌ | ❌ | ✅ |
| **LAW retention** | 30 days | 30 days | 30 days | 90 days |
| **Auto-shutdown** | ✅ 23:00 UTC | ✅ 23:00 UTC | ✅ 23:00 UTC | ❌ |
| **Public IP** | ✅ | ❌ | ❌ | ❌ |
| **Access** | SSH tunnel | BeyondTrust | BeyondTrust | BeyondTrust |
| **Est. cost (light use)** | ~$16/mo | ~$45/mo | ~$28/mo | ~$55/mo |

> **corp-preprod** and **corp-prod** use containerised deployment in AKS — no Bicep profile needed.

---

## Repository Structure

```
.
├── main.bicep              # Azure infrastructure — profile-aware (lab/preprod/production/corp-lab)
├── main.bicepparam         # Parameters (SSH key, profile, region, BeyondTrust CIDR)
├── deploy.sh               # Step 1: interactive profile selector → deploys infra
├── teardown.sh             # Destroys all Azure resources + cleans up local state
│
├── setup_vm.sh             # Step 2: VM bootstrap — accepts --profile lab|preprod|production
├── proxy.py                # Step 2: LlamaFirewall FastAPI proxy — 6-layer scanner stack
├── test_tunnel.sh          # Step 2: SSH tunnel + smoke test (home profiles)
│
├── Dockerfile              # AKS deployment — CPU build (corp-preprod)
├── Dockerfile.gpu          # AKS deployment — GPU build (corp-prod)
├── .dockerignore           # Excludes infra/PyRIT/secrets from Docker build context
│
├── setup_pyrit.sh          # Step 3: creates local venv + installs PyRIT
├── pyrit_redteam.py        # Step 3: red-team script (--endpoint, --category, --prompts-file)
├── custom_attacks.yaml     # Step 3: 87-prompt adversarial dataset (10 categories, PT-BR)
├── attack_prompts.yaml     # Step 3: extended built-in attack library
├── gandalf_attacks.yaml    # Step 3: 60-prompt Gandalf dataset (English, 3 Lakera sources)
├── build_gandalf_dataset.py   # Step 3: downloads + curates Gandalf datasets from HuggingFace
├── social_engineering_pt.nov  # NOVA rules — 10 rules covering PT-BR + Gandalf attack patterns
├── canary_probe.py         # Production monitoring — 10-probe hourly canary + nightly full run
├── .gitlab-ci.yml          # GitLab CI — manual PyRIT regression pipeline
│
├── log_shipper.py          # Step 4: ships PyRIT results + live events to LAW / Sentinel
│
├── workbook_content.json   # Step 5: Azure Workbook definition
├── deploy_workbook.py      # Step 5: deploys workbook (reuses same ID on redeploy)
│
├── run_demo.sh             # Demo: preflight → PyRIT → log ship — one command
├── toggle_nollm.sh         # Toggle Ollama bypass for fast PyRIT runs
├── toggle_bypass.sh        # Toggle full firewall bypass (incident response)
│
├── deploy-outputs.json     # Generated by deploy.sh — gitignored, keep locally
└── README.md
```

> `deploy-outputs.json` is excluded from git (`.gitignore`) — contains your LAW primary key.

---

## Prerequisites

- Azure subscription (personal is fine for home profiles)
- Azure CLI installed and logged in (`az login`)
- Linux laptop with Python 3.10+, `ssh`, `jq`
- HuggingFace account with access to [meta-llama/Llama-Prompt-Guard-2-86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
- HuggingFace read token from https://huggingface.co/settings/tokens

After cloning, make all scripts executable:
```bash
chmod +x *.sh
```

> LlamaGuard 3:8B is pulled via Ollama — no HuggingFace token needed for it.

---

## HuggingFace Setup — Do This Before Step 2

PromptGuard 2 is a gated Meta model. One-time setup:

**1.** Create a free account at https://huggingface.co/join

**2.** Accept the model licence at https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M
— click **"Agree and access repository"** (instant approval)

**3.** Generate a read token at https://huggingface.co/settings/tokens
→ **New token** → Role: **Read** → copy it

> `setup_vm.sh` will prompt for this token interactively and inject it into
> the systemd service. After first download the weights are cached locally.

---

## Step 1 — Deploy Azure Infrastructure

```bash
cd ~/Documents/Safra_AI_Defense

# 1. Generate SSH key — skip if you already have one.
#    Check first: ls ~/.ssh/id_ed25519.pub
#    If the file exists, skip to step 2.
#    If not, generate one:
ssh-keygen -t ed25519 -C "llamapoc"

# 2. Copy your public key into main.bicepparam
#    Open the file and replace the adminPublicKey value with the output below:
cat ~/.ssh/id_ed25519.pub
#    It should look like: param adminPublicKey = 'ssh-ed25519 AAAAC3Nz... your-key-here'
#    ⚠️  Do this before running deploy.sh — the script will stop if the
#    placeholder value hasn't been replaced.

# 3. Deploy — the script will prompt for profile
chmod +x deploy.sh && ./deploy.sh
```

The profile selector appears after confirming the subscription:

```
1) lab         — Standard_B8ms   · phi3:mini   · ~$16/month
2) preprod     — Standard_D8s_v3  · mistral:7b  · ~$28/month
3) production  — Standard_D16s_v3 · llama3:8b   · ~$55/month
4) corp-lab    — NC4as_T4_v3 GPU + B2ms PyRIT VM · ~$45/month
                 ⚠️  Requires NC-series quota in sandbox subscription
```

> **corp-lab** auto-generates a dedicated SSH key pair at `~/.ssh/id_ed25519_llamapoc_corp`.
> Do NOT reuse your personal key in a corporate environment.

---

## Step 2 — Set Up the VM (home profiles)

```bash
# Copy scripts to VM (all three required)
scp setup_vm.sh proxy.py social_engineering_pt.nov \
  azureuser@llamapoc-llama.eastus.cloudapp.azure.com:~/

# Run setup — pass profile or let it prompt
ssh azureuser@llamapoc-llama.eastus.cloudapp.azure.com \
  'bash ~/setup_vm.sh --profile lab 2>&1 | tee ~/setup.log'
```

| Step | What happens |
|---|---|
| apt | System update + wait for apt-lock |
| Ollama | Installs + pulls LLM model for the profile |
| LlamaGuard3 | `ollama pull llama-guard3:8b` (~4.7 GB) |
| Python | venv + llamafirewall + transformers + torch + nova-hunting |
| HfFolder patch | Compatibility shim for huggingface_hub >= 0.25 |
| HF login | Interactive prompt for your token + PromptGuard 2 download (~170 MB) |
| proxy.py | Deployed with profile-specific environment variables |
| NOVA | Official rules cloned + custom rules deployed |
| systemd | `ollama.service` + `llamafirewall.service` enabled and started |

**Expected runtime:** lab ~20 min · preprod ~35 min · production ~45 min

**Validate:**
```bash
./test_tunnel.sh azureuser@llamapoc-llama.eastus.cloudapp.azure.com
```

Expected: `/health` shows 6 active scanners, clean prompt → ALLOW, injection → BLOCK.

**Always warm up models before running PyRIT** — cold models cause LlamaGuard3 to timeout on first request:

```bash
ssh azureuser@llamapoc-llama.eastus.cloudapp.azure.com << 'EOF'
curl -sf http://localhost:11434/api/generate \
  -d '{"model":"llama-guard3:8b","prompt":"hello","stream":false}' > /dev/null && echo "llama-guard3 warm"
curl -sf http://localhost:11434/api/generate \
  -d '{"model":"phi3:mini","prompt":"hello","stream":false}' > /dev/null && echo "phi3:mini warm"
EOF
```

> Replace `phi3:mini` with `mistral:7b` or `llama3:8b` for preprod/production profiles.

**Known issues handled by the script:**
1. apt lock on first boot — waits up to 2 min then force-clears
2. `ollama run` CLI hangs — smoke test uses REST API with `--max-time 60`
3. `huggingface_hub >= 0.25` — `HfFolder` removed, script applies compatibility shim
4. LlamaFirewall `scanners` must be a dict — `{Role: [ScannerType]}`
5. Blocking scan in async handler — `firewall.scan()` wrapped in `asyncio.to_thread()`

---

## Step 3 — Run PyRIT Red-Team (from your laptop)

```bash
# Install (one-time)
chmod +x setup_pyrit.sh && ./setup_pyrit.sh

# Open tunnel + warm models first (home profiles)
./test_tunnel.sh azureuser@llamapoc-llama.eastus.cloudapp.azure.com

# Run full 87-prompt dataset
source venv/bin/activate
python3 pyrit_redteam.py --prompts-file custom_attacks.yaml

# Run against a specific endpoint (corp-lab — private IP)
python3 pyrit_redteam.py \
  --endpoint http://10.0.0.4:8080/v1 \
  --prompts-file custom_attacks.yaml

# Run a single category
python3 pyrit_redteam.py --prompts-file custom_attacks.yaml --category jailbreak

# Dry run — validates endpoint only
python3 pyrit_redteam.py --dry-run
```

**Attack categories in `custom_attacks.yaml` (87 prompts, Brazilian Portuguese):**

| Category | Count | Notes |
|---|---|---|
| `jailbreak` | 32 | DAN, developer mode, roleplay, fictional framing |
| `evasion` | 17 | BiDi text, homoglyphs, code-switching, encoding |
| `social_engineering` | 12 | Coercion, impersonation, emotional manipulation |
| `content_safety` | 7 | XSS, SQL injection, harmful content |
| `baseline` | 6 | Should all pass — validates legitimate traffic |
| `prompt_injection` | 4 | Classic injection patterns |
| `reliability` | 3 | Edge cases, should all pass |
| `data_leakage` | 3 | Credential extraction, source code exfiltration |
| `tool_abuse` | 2 | Command injection, dangerous function calls |
| `policy_compliance` | 1 | Regulatory bypass |

**Gandalf dataset `gandalf_attacks.yaml` (60 prompts, English):**

Real human-generated attacks from Lakera's Gandalf red-teaming game — curated from three HuggingFace datasets. Use for cross-dataset validation alongside `custom_attacks.yaml`.

| Category | Count | Source | Notes |
|---|---|---|---|
| `prompt_injection` | 25 | `gandalf_ignore_instructions` | Classic "ignore previous instructions" variants |
| `indirect_injection` | 20 | `gandalf_summarization` | Injection hidden inside document summarisation tasks |
| `evasion` | 15 | `mosscap_prompt_injection` | DEF CON 2023 variant — acrostics, encoding, roleplay |

```bash
# Rebuild the dataset (re-downloads from HuggingFace)
pip install datasets
python3 build_gandalf_dataset.py

# Run against LlamaFirewall
python3 pyrit_redteam.py --prompts-file gandalf_attacks.yaml
```

**Detection results — Gandalf dataset (first run):**

| Category | Pass rate | Notes |
|---|---|---|
| `prompt_injection` | 100% | PromptGuard 2 catches all classic injection syntax |
| `indirect_injection` | 50% | Hardest category — attacks hidden in document content |
| `evasion` | 47% | Multi-step transformation and fictional framing attacks |
| **Overall** | **70%** | Real-world attacks, no PT-BR tuning |

> The gap vs `custom_attacks.yaml` (98.85%) is expected — the Gandalf dataset tests generalisation beyond the language and patterns the stack was tuned against.

**Detection rate progression:**

| Run | Config | Pass rate |
|---|---|---|
| 1 | PromptGuard 2 only (threshold 0.50) | 43.68% |
| 2 | PromptGuard 2 (threshold 0.05) | 60.92% |
| 3 | + HiddenASCII + Regex + CustomPatterns | 72.41% |
| 4 | + LlamaGuard 3:8B | 80.46% |
| 5 | + dataset fixes + input truncation | 88.51% |
| 6 | + fail-closed on timeout | 90.80% |
| **7** | **+ NOVA (keyword + semantic)** | **98.85%** |

---

## NO_LLM Mode — Speed Up PyRIT Runs

Bypasses Ollama for allowed prompts — only the firewall scanner stack runs.
Cuts per-prompt latency from ~23s down to ~7s.

```bash
./toggle_nollm.sh on    # enable (fast mode)
./toggle_nollm.sh off   # disable (full LLM responses)
./toggle_nollm.sh status
```

---

## Step 4 — Ship Logs to Log Analytics

```bash
source venv/bin/activate

# After a PyRIT session
python3 log_shipper.py --mode pyrit

# Target corporate Sentinel LAW instead of the PoC workspace
python3 log_shipper.py --mode pyrit \
  --workspace-id <sentinel-workspace-id> \
  --workspace-key <sentinel-primary-key>

# Stream live events during a test
python3 log_shipper.py --mode live \
  --vm-host azureuser@llamapoc-llama.eastus.cloudapp.azure.com
```

> Sentinel workspace credentials: Portal → Log Analytics → your workspace → Agents → Primary key

---

## Step 5 — Deploy Azure Workbook

> ⚠️ **Requires Azure CLI (`az`)** — run from your laptop or Azure Cloud Shell.
> Do NOT run from the PyRIT or LlamaFirewall VMs (no `az` installed there).

```bash
# Home-lab — reads credentials from deploy-outputs.json
source venv/bin/activate
python3 deploy_workbook.py

# Corp / Sentinel LAW — pass credentials directly (no deploy-outputs.json needed)
# Cloud Shell: install httpx first: pip install httpx --user --quiet
python3 deploy_workbook.py \
  --workspace-id <sentinel-workspace-id> \
  --resource-id /subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>
```

> Find your Sentinel workspace resource ID: Portal → Log Analytics workspaces → your workspace → Properties → Resource ID

The workbook ID is persisted in `deploy-outputs.json` — re-running updates the
existing workbook in-place without creating duplicates.

**Azure Portal → Monitor → Workbooks → LlamaFirewall Security Dashboard**

---

## Prompt Logging to Sentinel

LlamaFirewall can ship the **full prompt text** of every request to a dedicated
`LlamaFirewallPrompts_CL` table in your Sentinel LAW. This table is kept separate
from the general `LlamaFirewallEvents_CL` table and restricted to incident
investigators via table-level RBAC.

**Use cases:**
- Incident investigation — a user complains their query was blocked; you see exactly what they sent
- Threat hunting — a malicious prompt was allowed; you need the full text for analysis
- Compliance audit — full record of what the LLM gateway received

> ⚠️ **Data governance note:** Full prompts may contain PII (CPF, names, account numbers).
> Always configure table-level RBAC before enabling in production.
> In lab/corp-lab, prompts are synthetic attack data — PII redaction is optional.

---

### Step 1 — Restrict access to LlamaFirewallPrompts_CL in LAW

**Portal → Sentinel LAW → Access control (IAM) → Add role assignment**

1. Create a custom role allowing only `LlamaFirewallPrompts_CL`:
```json
{
  "Name": "LlamaFirewall Prompt Investigator",
  "Actions": [
    "Microsoft.OperationalInsights/workspaces/read",
    "Microsoft.OperationalInsights/workspaces/query/read"
  ],
  "DataActions": [
    "Microsoft.OperationalInsights/workspaces/query/LlamaFirewallPrompts_CL/read"
  ]
}
```

2. Assign the role to your incident investigator security group (1-2 groups max)
3. Verify general Sentinel readers **cannot** query `LlamaFirewallPrompts_CL`

---

### Step 2 — Enable prompt logging on the LlamaFirewall VM

**Lab / corp-lab (Shared Key):**
```bash
sudo systemctl set-environment PROMPT_LOGGING_ENABLED=1
sudo systemctl set-environment LAW_WORKSPACE_ID=<your-sentinel-workspace-id>
sudo systemctl set-environment LAW_WORKSPACE_KEY=<your-sentinel-primary-key>
sudo systemctl restart llamafirewall

# Verify
curl -sf http://localhost:8080/health | python3 -m json.tool
# → "prompt_logging": true, "ingestion_method": "shared_key"
```

**Preprod / production (Managed Identity — no keys):**

The VM already has a System-Assigned Managed Identity and the DCR role assignment from the Bicep deployment. Get the DCE endpoint and DCR immutable ID from `deploy-outputs.json`:

```bash
cat deploy-outputs.json | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('DCE:', d.get('dceEndpoint',{}).get('value'))
print('DCR:', d.get('dcrImmutableId',{}).get('value'))
"

# On the LlamaFirewall VM:
sudo systemctl set-environment PROMPT_LOGGING_ENABLED=1
sudo systemctl set-environment DCE_ENDPOINT=<dce-endpoint>
sudo systemctl set-environment DCR_IMMUTABLE_ID=<dcr-immutable-id>
# LAW_INGESTION_METHOD=managed_identity is already set by setup_vm.sh for preprod/production
sudo systemctl restart llamafirewall

# Verify
curl -sf http://localhost:8080/health | python3 -m json.tool
# → "prompt_logging": true, "ingestion_method": "managed_identity"
```

> The Managed Identity token is fetched automatically from the Azure IMDS endpoint
> (`169.254.169.254`) inside the VM. Tokens are cached and refreshed 5 minutes before
> expiry. No credentials are stored anywhere.

---

### Step 3 — Enable PII redaction (production only)

In production, enable redaction via Azure AI Language before prompts land in LAW:

```bash
sudo systemctl set-environment PII_REDACTION_ENABLED=1
sudo systemctl set-environment AZURE_LANGUAGE_ENDPOINT=https://<your-resource>.cognitiveservices.azure.com
sudo systemctl set-environment AZURE_LANGUAGE_KEY=<your-language-key>
sudo systemctl restart llamafirewall
```

The API masks detected PII entities (CPF, names, emails, phone numbers, account numbers)
with `*` characters before the prompt is shipped to LAW. The original unredacted prompt
remains in VM journald only.

> PII redaction is **fail-open** — if the API is unavailable, the prompt ships as-is
> rather than blocking the request. For stricter control, set `PII_REDACTION_ENABLED=1`
> alongside a Sentinel Analytics Rule that alerts on `pii_redacted: false` records.

---

### Step 4 — Query prompts in Sentinel

```kusto
// All prompts in the last 24 hours
LlamaFirewallPrompts_CL
| where TimeGenerated > ago(24h)
| project TimeGenerated, request_id_s, scan_decision_s, blocked_b,
          scan_score_d, full_prompt_s
| order by TimeGenerated desc

// Blocked prompts only — for threat hunting
LlamaFirewallPrompts_CL
| where TimeGenerated > ago(7d) and blocked_b == true
| project TimeGenerated, scan_decision_s, scan_reason_s,
          scan_score_d, full_prompt_s
| order by scan_score_d desc

// Investigate a specific request by ID
LlamaFirewallPrompts_CL
| where request_id_s == "<request-id-from-user-complaint>"
| project TimeGenerated, full_prompt_s, scan_decision_s,
          scan_reason_s, scan_score_d, pii_redacted_b
```

---

### AKS / production — env vars via Kubernetes Secret

In production (AKS pod), set via Kubernetes Secret instead of systemd:

```bash
kubectl create secret generic llamafirewall-prompt-logging \
  --namespace llamafirewall \
  --from-literal=PROMPT_LOGGING_ENABLED=1 \
  --from-literal=LAW_WORKSPACE_ID=<id> \
  --from-literal=LAW_WORKSPACE_KEY=<key> \
  --from-literal=PII_REDACTION_ENABLED=1 \
  --from-literal=AZURE_LANGUAGE_ENDPOINT=<endpoint> \
  --from-literal=AZURE_LANGUAGE_KEY=<key>
```

---

When legitimate traffic is being dropped by LlamaFirewall, enable bypass mode.
The proxy stays running — no network changes needed. All bypassed requests are
still logged to Sentinel with `scan_decision: BYPASS` for audit trail.

**Home profiles (VM):**
```bash
./toggle_bypass.sh on    # disable scanning — forward directly to Ollama
./toggle_bypass.sh off   # re-enable scanning
./toggle_bypass.sh status
```

**Corp-preprod / corp-prod (AKS):**
```bash
kubectl set env deployment/llamafirewall BYPASS_MODE=1 -n llamafirewall
# Re-enable when resolved:
kubectl set env deployment/llamafirewall BYPASS_MODE=0 -n llamafirewall
```

---

## Corp-Lab Deployment

Two VMs in an isolated sandbox subscription. BeyondTrust for access, no SSH tunnel.

**Prerequisites:**
1. NC-series quota approved in sandbox subscription — Portal → Subscriptions → Usage + quotas → Request increase (Standard NCASv3_T4 Family, minimum 4 vCPUs)
2. Set `beyondTrustSourceCIDR` in `main.bicepparam` to your BeyondTrust IP (e.g. `'203.0.113.10/32'`)
3. **Trusted Launch is automatically disabled** in Bicep for all corp profiles — required for NVIDIA GPU driver to bind correctly. Do not re-enable it.
4. **Register the StandardSecurityType feature** in the sandbox subscription — required for deploying VMs with Trusted Launch disabled. Run once per subscription:
   ```bash
   az feature register \
     --namespace Microsoft.Compute \
     --name UseStandardSecurityType
   # Wait for state to show "Registered" (~1-2 minutes)
   az feature show \
     --namespace Microsoft.Compute \
     --name UseStandardSecurityType \
     --query properties.state
   ```
5. When connecting via Bastion, GitHub requires a Personal Access Token for git clone (password auth disabled) — generate at: github.com → Settings → Developer settings → Personal access tokens → repo scope

**Deploy:**
```bash
./deploy.sh
# → y → 4 (corp-lab)
# → Dedicated SSH key auto-generated at ~/.ssh/id_ed25519_llamapoc_corp
# → Press Enter to continue
```

Outputs after deployment:
- **LlamaFirewall private IP** — PyRIT connects here (e.g. `10.0.0.4`)
- **PyRIT VM FQDN** — BeyondTrust access for red-team sessions
- **LlamaFirewall VM FQDN** — BeyondTrust access for admin/setup

**Set up LlamaFirewall VM:**
```bash
# Connect via Bastion → SSH terminal opens in browser
# Clone the repo (GitHub requires a Personal Access Token — password auth is disabled)
# Generate one at: github.com → Settings → Developer settings → Personal access tokens
# Scope: repo · Expiration: 7 days is enough
git clone https://<your-github-username>:<YOUR_PAT>@github.com/VinnieFreitas/llamafirewall-pyrit-poc.git
cd llamafirewall-pyrit-poc
chmod +x *.sh

# Run setup — detects repo location automatically (no scp needed)
bash setup_vm.sh --profile lab 2>&1 | tee ~/setup.log

# After setup — manually copy NOVA rules if needed
sudo cp social_engineering_pt.nov /opt/llamafirewall/nova-rules-custom/
sudo systemctl restart llamafirewall
curl -sf http://localhost:8080/health  # should show NOVA(10rules)
```

**Set up PyRIT VM:**
```bash
# Connect via Bastion → SSH terminal opens in browser
git clone https://<your-github-username>:<YOUR_PAT>@github.com/VinnieFreitas/llamafirewall-pyrit-poc.git
cd llamafirewall-pyrit-poc
chmod +x *.sh

# Install PyRIT
sudo apt install python3.10-venv -y
./setup_pyrit.sh
source venv/bin/activate
```

**Run PyRIT** — no SSH tunnel, direct private IP:
```bash
python3 pyrit_redteam.py \
  --endpoint http://<lf-private-ip>:8080/v1 \
  --prompts-file custom_attacks.yaml
```

**Ship to Sentinel:**
```bash
python3 log_shipper.py --mode pyrit \
  --workspace-id <sentinel-workspace-id> \
  --workspace-key <sentinel-primary-key>
```

---

## Corp-Preprod Deployment

LlamaFirewall runs as a container in your AKS cluster. PyRIT runs as a GitLab CI job.

**Architecture:**
```
GitLab CI (PyRIT job)
    │  --endpoint http://llamafirewall-svc:8080/v1
    ▼
AKS → LlamaFirewall pod (CPU) → Azure OpenAI (private endpoint)
```

**1. Build and push CPU image:**
```bash
docker build -t <acr>.azurecr.io/llamafirewall-proxy:preprod \
  --build-arg HF_TOKEN=<hf-token> -f Dockerfile .
az acr login --name <acr>
docker push <acr>.azurecr.io/llamafirewall-proxy:preprod
```

**2. Deploy to AKS:**
```bash
kubectl create namespace llamafirewall
kubectl create secret generic llamafirewall-secrets \
  --namespace llamafirewall \
  --from-literal=HF_TOKEN=<hf-token> \
  --from-literal=SENTINEL_WORKSPACE_ID=<id> \
  --from-literal=SENTINEL_WORKSPACE_KEY=<key>
kubectl apply -f k8s/llamafirewall-preprod.yaml
```

**3. Point backend at LlamaFirewall — one env var change:**
```bash
kubectl set env deployment/backend \
  OPENAI_ENDPOINT=http://llamafirewall-svc.llamafirewall.svc.cluster.local:8080/v1 \
  -n <backend-namespace>
```

**4. Configure GitLab CI variables** (Settings → CI/CD → Variables → mark as Masked):

| Variable | Value |
|---|---|
| `LLAMAFIREWALL_ENDPOINT` | `http://llamafirewall-svc.llamafirewall.svc.cluster.local:8080/v1` |
| `SENTINEL_WORKSPACE_ID` | your Sentinel workspace ID |
| `SENTINEL_WORKSPACE_KEY` | your Sentinel primary key |

Update `YOUR_RUNNER_TAG_HERE` in `.gitlab-ci.yml` with the runner tag your DevOps team confirms.

---

## Corp-Prod Deployment

Same AKS architecture as preprod — GPU node pool, production profile, hourly canary probe.

**Architecture:**
```
User → EntraID → Angular SPA (AKS)
                      │
                 Backend (AKS)  [one env var: OPENAI_ENDPOINT]
                      │
              LlamaFirewall pod (AKS — GPU node pool)
                      │
              Azure OpenAI (private endpoint, different subscription)

              Canary CronJob (AKS) → Sentinel LAW → Alerts
```

**1. Build and push GPU image:**
```bash
docker build -t <acr>.azurecr.io/llamafirewall-proxy:prod \
  --build-arg HF_TOKEN=<hf-token> -f Dockerfile.gpu .
docker push <acr>.azurecr.io/llamafirewall-proxy:prod
```

**2. Deploy to GPU node pool** — add to pod spec:
```yaml
resources:
  requests:
    nvidia.com/gpu: 1
  limits:
    nvidia.com/gpu: 1
```

**3. Deploy canary CronJob** (runs every hour automatically):
```bash
kubectl apply -f k8s/canary-cronjob.yaml -n llamafirewall
```

Manual canary run at any time:
```bash
python3 canary_probe.py --mode canary \
  --endpoint http://llamafirewall-svc.llamafirewall.svc.cluster.local:8080/v1 \
  --workspace-id <sentinel-id> --workspace-key <sentinel-key>
```

**4. Sentinel alert** — create an Analytics Rule:
```kusto
LlamaFirewallCanary_CL
| where TimeGenerated > ago(2h)
| where canary_run_type_s == "canary"
| summarize pass_rate = avg(pass_rate_d) by bin(TimeGenerated, 1h)
| where pass_rate < 90
```

---

## Cost Management

```bash
# Deallocate VM when done (stops compute billing, keeps disk)
az vm deallocate --resource-group rg-llamapoc --name llamapoc-vm --no-wait

# Start again when needed
az vm start --resource-group rg-llamapoc --name llamapoc-vm
```

**Cost by profile (light usage ~20 hrs/month active):**

| Profile | VM | Storage | LAW | Total |
|---|---|---|---|---|
| lab | ~$8 (B8ms) | ~$5 | Free | **~$16/month** |
| preprod | ~$15 (D8s_v3) | ~$8 | Free | **~$28/month** |
| production | ~$32 (D16s_v3) | ~$15 | ~$5 | **~$55/month** |
| corp-lab | ~$30 (NC4as+B2ms) | ~$10 | Free | **~$45/month** |

> Production and corp-prod have no auto-shutdown — remember to deallocate manually.

---

## Teardown

```bash
# 1. Close SSH tunnel (home profiles)
kill $(cat /tmp/llamapoc_tunnel.pid)

# 2. Deallocate VM
az vm deallocate --resource-group rg-llamapoc --name llamapoc-vm --no-wait
```

> ⚠️ **Deallocate ≠ Shutdown.** `sudo shutdown` keeps billing. Always use `az vm deallocate`.

**Resuming:**
```bash
az vm start --resource-group rg-llamapoc --name llamapoc-vm
./test_tunnel.sh azureuser@llamapoc-llama.eastus.cloudapp.azure.com
# Warm up models before running PyRIT
ssh azureuser@llamapoc-llama.eastus.cloudapp.azure.com << 'EOF'
curl -sf http://localhost:11434/api/generate \
  -d '{"model":"llama-guard3:8b","prompt":"hello","stream":false}' > /dev/null && echo "llama-guard3 warm"
curl -sf http://localhost:11434/api/generate \
  -d '{"model":"phi3:mini","prompt":"hello","stream":false}' > /dev/null && echo "phi3:mini warm"
EOF
```

**Full destroy:**
```bash
./teardown.sh
```

---

## Production Hardening Roadmap

**Implemented:**

| ✅ | Scanner | What it catches |
|---|---|---|
| ✅ | PromptGuard 2 | Injection syntax, jailbreak patterns |
| ✅ | HiddenASCII | BiDi text, invisible chars, encoding tricks |
| ✅ | Regex + CustomPatterns | XSS, SQL, credentials, tool abuse |
| ✅ | LlamaGuard 3:8B | Social engineering, content safety |
| ✅ | NOVA (keyword+semantic) | Logic traps, tool injection, bioweapon synthesis |
| ✅ (preprod+prod) | Output scanning | Harmful content in LLM responses |

**Roadmap:**

| Gap | Notes | Fix |
|---|---|---|
| NOVA LLM tier | Disabled — phi3:mini caused false positives | Dedicated safety classifier on GPU |
| GPU inference | CPU averages ~23s/prompt | NC-series T4 → ~1-2s/prompt (implemented in corp-lab/prod) |
| Kubernetes manifests | k8s/ folder referenced but not yet committed | Add Deployment, Service, ConfigMap, CronJob YAMLs |
| GitLab runner tag | `YOUR_RUNNER_TAG_HERE` placeholder in `.gitlab-ci.yml` | Update when DevOps confirms runner type |

---

## Security Notes

- `deploy-outputs.json` contains your LAW primary key — **never commit this file**
- Home profiles: NSG allows SSH from any IP — restrict `sourceAddressPrefix` in `main.bicep` for production use
- Corp-lab: NSG restricts SSH to BeyondTrust source CIDR only
- LlamaFirewall proxy binds to `127.0.0.1` on VMs — only reachable via SSH tunnel or internal VNet
- HuggingFace token is injected into systemd env / Kubernetes secret — never stored in config files
- Corp SSH key (`id_ed25519_llamapoc_corp`) is separate from personal key — never reuse personal keys in corporate environments
