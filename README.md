# LlamaFirewall + PyRIT — Azure Security PoC

A personal lab proof-of-concept demonstrating a self-hosted LLM security pipeline on Azure:

```
[ Linux Laptop ]                        [ Azure ~$10/month ]
  PyRIT ──── SSH tunnel ──────────────► LlamaFirewall proxy (:8080)
  log_shipper ────────────────────────►        │
                                         Ollama + Phi-3-mini (:11434)
                                               │
                                         Log Analytics Workspace
                                               │
                                         Azure Workbook Dashboard
```

**Stack:**
- **LLM**: [Ollama](https://ollama.com) + [Phi-3-mini](https://ollama.com/library/phi3) (CPU-only, ~2.3 GB)
- **Firewall**: [LlamaFirewall](https://github.com/meta-llama/LlamaFirewall) with [PromptGuard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) (86M params)
- **Red-team**: [PyRIT](https://github.com/Azure/PyRIT) — 18 adversarial prompts across 6 attack categories
- **Observability**: Azure Log Analytics → Azure Workbook

---

## Repository Structure

```
.
├── step1-infrastructure/
│   ├── main.bicep           # VM + Log Analytics Workspace
│   ├── main.bicepparam      # Parameters (fill in your SSH key)
│   └── deploy.sh            # Deployment script
│
├── step2-vm-setup/
│   ├── setup_vm.sh          # Full VM bootstrap (copy to VM and run)
│   ├── proxy.py             # LlamaFirewall FastAPI proxy (copy to VM)
│   └── test_tunnel.sh       # Laptop-side tunnel + smoke test
│
├── step3-pyrit/
│   ├── setup_pyrit.sh       # Laptop: create venv + install PyRIT
│   └── pyrit_redteam.py     # 18-prompt red-team script
│
├── step4-log-shipper/
│   └── log_shipper.py       # Ships PyRIT results + live events to LAW
│
├── step5-workbook/
│   ├── workbook_content.json  # Workbook definition
│   └── deploy_workbook.py     # Deploys workbook via Azure REST API
│
└── README.md
```

---

## Prerequisites

- Azure subscription (personal is fine)
- Azure CLI installed and logged in (`az login`)
- Linux laptop with Python 3.10+, `ssh`, `jq`
- HuggingFace account with access to [meta-llama/Llama-Prompt-Guard-2-86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
- HuggingFace read token from https://huggingface.co/settings/tokens

---

## Step 1 — Deploy Azure Infrastructure

```bash
cd step1-infrastructure/

# 1. Generate SSH key (skip if you have one)
ssh-keygen -t ed25519 -C "llamapoc"

# 2. Edit main.bicepparam — paste your public key, choose a region
cat ~/.ssh/id_ed25519.pub   # copy this into main.bicepparam

# 3. Deploy (~3 minutes)
chmod +x deploy.sh && ./deploy.sh
```

**What gets created:**
- Standard_B4ms VM (4 vCPU, 16 GB RAM) — Ubuntu 22.04 LTS
- Standard SSD 64 GB OS disk
- VNet + NSG (SSH only, port 22)
- Static public IP with DNS label
- Log Analytics Workspace (PerGB2018, 30-day retention)
- Auto-shutdown schedule (23:00 UTC daily)

**Estimated cost:** ~$9–15/month if deallocated when not in use.

---

## Step 2 — Set Up the VM

```bash
cd step2-vm-setup/

# Copy scripts to VM
scp setup_vm.sh proxy.py azureuser@llamapoc-llama.eastus.cloudapp.azure.com:~/

# Run setup (~15-20 min — model downloads are the slow parts)
ssh azureuser@llamapoc-llama.eastus.cloudapp.azure.com \
  'bash ~/setup_vm.sh 2>&1 | tee ~/setup.log'
```

The script will prompt you interactively for your HuggingFace token during the PromptGuard 2 model download.

**Known issues fixed in this script (documented for future reference):**
1. **apt lock on first boot** — Azure runs `unattended-upgrades` in the background. The script waits up to 2 minutes, then force-clears the lock.
2. **`ollama run` CLI hangs** — Smoke test uses the REST API (`/api/generate`) instead of `ollama run`, which blocks in non-interactive shells.
3. **`huggingface_hub >= 0.25` breaks LlamaFirewall** — `HfFolder` was removed in v0.25. The script patches `promptguard_utils.py` with a compatibility shim.
4. **LlamaFirewall `scanners` must be a dict** — The `LlamaFirewall` constructor takes `{Role: [ScannerType]}`, not a flat list.
5. **Blocking scan in async handler** — `firewall.scan()` is synchronous. `proxy.py` wraps it with `asyncio.to_thread()` to avoid freezing uvicorn's event loop.

**Validate from your laptop:**
```bash
chmod +x test_tunnel.sh
./test_tunnel.sh azureuser@llamapoc-llama.eastus.cloudapp.azure.com
```

Expected output: clean prompt → ALLOW (score ~0.0003), DAN injection → BLOCK (score ~0.999).

---

## Step 3 — Run PyRIT Red-Team (from your laptop)

```bash
cd step3-pyrit/

# Install (one-time)
# If you get python3-venv error: sudo apt install python3.10-venv -y
chmod +x setup_pyrit.sh && ./setup_pyrit.sh

# Make sure the tunnel is open first
./test_tunnel.sh azureuser@llamapoc-llama.eastus.cloudapp.azure.com

# Run all 18 attack prompts
source venv/bin/activate
python3 pyrit_redteam.py

# Run a single category
python3 pyrit_redteam.py --category jailbreak
```

**Attack categories:**

| Category | Count | Notes |
|---|---|---|
| `baseline` | 3 | Should all pass — validates legitimate traffic |
| `prompt_injection` | 4 | Classic injection patterns |
| `jailbreak` | 4 | DAN, developer mode, roleplay, grandma exploit |
| `indirect_injection` | 2 | Payload buried in documents/URLs |
| `obfuscation` | 3 | Base64, leetspeak, token splitting — some may evade |
| `data_extraction` | 2 | System prompt leak, training data extraction |

**Observed results:** 83.3% pass rate (15/18). False negatives: `end_of_input_injection`, `grandma_exploit`, `training_data_extraction`.

---

## Step 4 — Ship Logs to Log Analytics

```bash
cd step4-log-shipper/

# Copy deploy-outputs.json from step1 to this directory
# Then activate the PyRIT venv (it has httpx installed)
source ../step3-pyrit/venv/bin/activate

# Ship PyRIT results (one-shot after each red-team session)
python3 log_shipper.py --mode pyrit

# Stream live firewall events during a test session
python3 log_shipper.py --mode live \
  --vm-host azureuser@llamapoc-llama.eastus.cloudapp.azure.com
```

**LAW query to verify data landed:**
```kusto
PyRITResults_CL
| order by TimeGenerated desc
| project TimeGenerated, Category, attack_name_s, outcome_s, decision_s, score_d
```

> Note: Log Analytics auto-types fields. `category` becomes `Category` (reserved word), `run_timestamp` becomes `run_timestamp_t` (datetime).

---

## Step 5 — Deploy Azure Workbook

```bash
cd step5-workbook/

# deploy-outputs.json must be in this directory
source ../step3-pyrit/venv/bin/activate
python3 deploy_workbook.py
```

Find the workbook at: **Azure Portal → Monitor → Workbooks → LlamaFirewall Security Dashboard**

**Dashboard sections:**
1. Session Overview (KPI tiles: total attacks, pass rate, blocked, false negatives)
2. Results by Attack Category (stacked bar)
3. PromptGuard Score per Attack (bar chart)
4. All Attack Results (colour-coded table)
5. False Negatives + Production Hardening Roadmap

---

## Cost Management

```bash
# Deallocate VM when not testing (stops compute billing, keeps disk)
az vm deallocate --resource-group rg-llamapoc --name llamapoc-vm

# Start it again when needed (~60 seconds to boot, services start automatically)
az vm start --resource-group rg-llamapoc --name llamapoc-vm

# Auto-shutdown is configured at 23:00 UTC daily as a safety net
```

**Monthly cost breakdown (light usage):**

| Resource | Cost |
|---|---|
| VM (B4ms, ~20 hrs active/month) | ~$4 |
| Standard SSD 64 GB | ~$5 |
| Log Analytics (< 1 GB) | Free tier |
| Public IP | ~$3 |
| **Total** | **~$12/month** |

---

## Production Hardening Roadmap

This PoC uses only PromptGuard 2 for input scanning. Production would add:

| Gap | Finding | Fix |
|---|---|---|
| Delimiter-based injection | `end_of_input_injection` | Input segmentation |
| Social engineering | `grandma_exploit` | Llama Guard 3 (content policy) |
| Data extraction | `training_data_extraction` | Output scanning + DLP |

---

## Security Notes

- `deploy-outputs.json` contains your Log Analytics primary key — **never commit this file**
- The NSG allows SSH from any IP by default — restrict to your home IP in `main.bicep`
- LlamaFirewall proxy listens on `127.0.0.1` only — only reachable via SSH tunnel
- HuggingFace token is injected into the systemd service environment — not stored in any file
