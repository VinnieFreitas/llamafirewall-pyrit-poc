#!/usr/bin/env python3
"""
=============================================================================
 LlamaFirewall / PyRIT PoC — Workbook Deployment (Step 5)

 Deploys the Azure Workbook using the Azure REST API.
 Reads workspace info from deploy-outputs.json or CLI flags.

 ⚠️  Requires Azure CLI (az) — run from your laptop or Azure Cloud Shell.
     NOT from the PyRIT/LlamaFirewall VMs (no az installed there).

 Usage:
   # Home-lab — reads from deploy-outputs.json
   python3 deploy_workbook.py

   # Corp / Sentinel LAW — pass credentials directly
   python3 deploy_workbook.py \
     --workspace-id <sentinel-workspace-id> \
     --workspace-key <sentinel-primary-key> \
     --resource-id /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>

   # Cloud Shell — install httpx first
   pip install httpx --user --quiet

 Requirements: Azure CLI logged in (az login)
=============================================================================
"""

import argparse
import json
import subprocess
import sys
import uuid
from pathlib import Path

# ---------------------------------------------------------------------------
#  Parse CLI arguments
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Deploy LlamaFirewall Azure Workbook",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--workspace-id",
        default=None,
        help="Log Analytics Workspace ID. Overrides deploy-outputs.json. "
             "Find it: Portal → Log Analytics → your workspace → Overview → Workspace ID",
    )
    parser.add_argument(
        "--workspace-key",
        default=None,
        help="Log Analytics primary key (not required for workbook deployment, "
             "kept for consistency with log_shipper.py).",
    )
    parser.add_argument(
        "--resource-id",
        default=None,
        help="Full LAW resource ID. Overrides deploy-outputs.json. "
             "Format: /subscriptions/<sub>/resourceGroups/<rg>/providers/"
             "Microsoft.OperationalInsights/workspaces/<name>",
    )
    return parser.parse_args()

# ---------------------------------------------------------------------------
#  Load deployment outputs — CLI flags take priority over deploy-outputs.json
# ---------------------------------------------------------------------------

def load_outputs(args) -> dict:
    # If all required CLI args provided — use them directly
    if args.workspace_id and args.resource_id:
        resource_id = args.resource_id
        return {
            "law_resource_id":  resource_id,
            "subscription_id":  resource_id.split("/")[2],
            "resource_group":   resource_id.split("/")[4],
            "law_workspace_id": args.workspace_id,
        }

    # Fall back to deploy-outputs.json
    p = Path("deploy-outputs.json")
    if not p.exists():
        print("ERROR: deploy-outputs.json not found and no CLI flags provided.")
        print("")
        print("  Option A — pass credentials directly:")
        print("    python3 deploy_workbook.py \\")
        print("      --workspace-id <id> \\")
        print("      --resource-id /subscriptions/<sub>/resourceGroups/<rg>/providers/")
        print("                    Microsoft.OperationalInsights/workspaces/<name>")
        print("")
        print("  Option B — copy deploy-outputs.json from where you ran deploy.sh")
        print("")
        print("  ⚠️  This script requires Azure CLI (az) — run from laptop or Cloud Shell,")
        print("      not from the PyRIT/LlamaFirewall VMs.")
        sys.exit(1)

    data = json.loads(p.read_text())

    def extract(key):
        v = data.get(key, {})
        return v.get("value", v) if isinstance(v, dict) else v

    # CLI flags override individual fields from JSON
    law_resource_id  = args.resource_id  or extract("lawResourceId")
    law_workspace_id = args.workspace_id or extract("lawWorkspaceId")

    return {
        "law_resource_id":  law_resource_id,
        "subscription_id":  law_resource_id.split("/")[2],
        "resource_group":   law_resource_id.split("/")[4],
        "law_workspace_id": law_workspace_id,
    }

# ---------------------------------------------------------------------------
#  Get Azure access token via CLI
# ---------------------------------------------------------------------------

def get_access_token() -> str:
    result = subprocess.run(
        ["az", "account", "get-access-token",
         "--query", "accessToken", "-o", "tsv"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("ERROR: Could not get Azure access token.")
        print("  Make sure you're logged in: az login")
        print(result.stderr)
        sys.exit(1)
    return result.stdout.strip()

# ---------------------------------------------------------------------------
#  Deploy workbook
# ---------------------------------------------------------------------------

def deploy_workbook(outputs: dict, token: str) -> str:
    import httpx

    workbook_content = Path("workbook_content.json").read_text()

    # ---------------------------------------------------------------------------
    #  Use a stable workbook ID stored in deploy-outputs.json.
    #  This means redeploying updates the existing workbook in-place instead
    #  of creating a new one every time.
    # ---------------------------------------------------------------------------
    outputs_file = Path("deploy-outputs.json")
    outputs_data = json.loads(outputs_file.read_text())

    def extract(key):
        v = outputs_data.get(key, {})
        return v.get("value", v) if isinstance(v, dict) else v

    workbook_id = extract("workbookId")
    if not workbook_id:
        # First deploy — generate a new ID and save it
        workbook_id = str(uuid.uuid4())
        outputs_data["workbookId"] = {"value": workbook_id}
        outputs_file.write_text(json.dumps(outputs_data, indent=2))
        print(f"  New workbook ID generated and saved to deploy-outputs.json")
    else:
        print(f"  Reusing existing workbook ID: {workbook_id[:8]}...")

    sub_id = outputs["subscription_id"]
    rg     = outputs["resource_group"]
    law_id = outputs["law_resource_id"]

    url = (
        f"https://management.azure.com/subscriptions/{sub_id}"
        f"/resourceGroups/{rg}"
        f"/providers/microsoft.insights/workbooks/{workbook_id}"
        f"?api-version=2022-04-01"
    )

    # Detect location from LAW resource
    law_location_result = subprocess.run(
        ["az", "monitor", "log-analytics", "workspace", "show",
         "--ids", law_id, "--query", "location", "-o", "tsv"],
        capture_output=True, text=True
    )
    location = law_location_result.stdout.strip() or "eastus"

    body = {
        "name":     workbook_id,
        "type":     "microsoft.insights/workbooks",
        "location": location,
        "kind":     "shared",
        "properties": {
            "displayName":    "LlamaFirewall Security Dashboard",
            "serializedData": workbook_content,
            "version":        "1.0",
            "sourceId":       law_id,
            "category":       "workbook",
        }
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }

    print(f"  Deploying workbook '{body['properties']['displayName']}'...")
    print(f"  Resource group : {rg}")
    print(f"  Location       : {location}")
    print(f"  Workbook ID    : {workbook_id}")

    resp = httpx.put(url, json=body, headers=headers, timeout=30.0)

    if resp.status_code in (200, 201):
        result = resp.json()
        portal_url = (
            f"https://portal.azure.com/#@/resource/subscriptions/{sub_id}"
            f"/resourceGroups/{rg}"
            f"/providers/microsoft.insights/workbooks/{workbook_id}"
            f"/overview"
        )
        return portal_url
    else:
        print(f"ERROR: API returned {resp.status_code}")
        print(resp.text[:500])
        sys.exit(1)

# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    args = parse_args()

    print("\n==> Loading deployment outputs...")
    outputs = load_outputs(args)
    print(f"  LAW resource: {outputs['law_resource_id']}")

    print("\n==> Getting Azure access token...")
    token = get_access_token()
    print("  Token obtained.")

    print("\n==> Deploying workbook...")
    portal_url = deploy_workbook(outputs, token)

    print(f"""
============================================================
  Workbook deployed successfully!
============================================================

  Open it in the Azure portal:

  https://portal.azure.com
  → Monitor → Workbooks
  → Look for "LlamaFirewall Security Dashboard"

  Or navigate directly:
  {portal_url}

  Sections in the workbook:
  ─────────────────────────
  1. Session Overview (KPI tiles)
     Total attacks · Pass rate · Blocked · False negatives

  2. Results by Attack Category (bar chart)

  3. PromptGuard Score per Attack (bar chart)

  4. All Attack Results (table with colour-coded outcomes)

  5. False Negatives (the production hardening roadmap)
============================================================
""")
