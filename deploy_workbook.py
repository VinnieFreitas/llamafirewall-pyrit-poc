#!/usr/bin/env python3
"""
=============================================================================
 LlamaFirewall / PyRIT PoC — Workbook Deployment (Step 5)

 Deploys the Azure Workbook using the Azure REST API.
 Reads workspace info from deploy-outputs.json (same folder).

 Usage:
   source venv/bin/activate
   python3 deploy_workbook.py

 Requirements: Azure CLI logged in (az login)
=============================================================================
"""

import json
import subprocess
import sys
import uuid
from pathlib import Path

# ---------------------------------------------------------------------------
#  Load deployment outputs
# ---------------------------------------------------------------------------

def load_outputs() -> dict:
    p = Path("deploy-outputs.json")
    if not p.exists():
        print("ERROR: deploy-outputs.json not found in current directory.")
        print("  Copy it from the folder where you ran deploy.sh.")
        sys.exit(1)
    data = json.loads(p.read_text())

    def extract(key):
        v = data.get(key, {})
        return v.get("value", v) if isinstance(v, dict) else v

    return {
        "law_resource_id":   extract("lawResourceId"),
        "subscription_id":   extract("lawResourceId").split("/")[2],
        "resource_group":    extract("lawResourceId").split("/")[4],
        "law_workspace_id":  extract("lawWorkspaceId"),
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

    workbook_id   = str(uuid.uuid4())
    sub_id        = outputs["subscription_id"]
    rg            = outputs["resource_group"]
    law_id        = outputs["law_resource_id"]

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
    print("\n==> Loading deployment outputs...")
    outputs = load_outputs()
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
