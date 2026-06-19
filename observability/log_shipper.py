"""
=============================================================================
 LlamaFirewall / PyRIT PoC — Log Shipper (Step 4)

 Ships two data streams to Log Analytics Workspace:

   1. PyRITResults_CL      — batch upload of redteam_results.json
                             (run once after each PyRIT session)

   2. LlamaFirewallEvents_CL — live firewall events streamed from
                               the VM's journalctl via SSH
                             (run continuously during test sessions)

 Usage:
   source venv/bin/activate

   # Ship PyRIT results (one-shot)
   python3 log_shipper.py --mode pyrit

   # Stream live firewall events from the VM
   python3 log_shipper.py --mode live --vm-host azureuser@<vm-fqdn>

   # Both: ship results then start streaming
   python3 log_shipper.py --mode both --vm-host azureuser@<vm-fqdn>

 Config is read from deploy-outputs.json (produced by deploy.sh).
 Override with --workspace-id and --workspace-key if needed.
=============================================================================
"""

import argparse
import base64
import hashlib
import hmac
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

# ---------------------------------------------------------------------------
#  Log Analytics HTTP Data Collector API
#  Docs: https://learn.microsoft.com/azure/azure-monitor/logs/data-collector-api
# ---------------------------------------------------------------------------

class LogAnalyticsShipper:
    """
    Ships JSON records to a Log Analytics custom table via the
    HTTP Data Collector API (workspace key auth).
    """

    def __init__(self, workspace_id: str, workspace_key: str):
        self.workspace_id  = workspace_id
        self.workspace_key = workspace_key
        self.base_url      = (
            f"https://{workspace_id}.ods.opinsights.azure.com"
            f"/api/logs?api-version=2016-04-01"
        )

    def _build_signature(self, date: str, content_length: int) -> str:
        """HMAC-SHA256 signature required by the Data Collector API."""
        string_to_hash = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{date}\n/api/logs"
        )
        decoded_key = base64.b64decode(self.workspace_key)
        signature   = base64.b64encode(
            hmac.new(decoded_key, string_to_hash.encode("utf-8"),
                     digestmod=hashlib.sha256).digest()
        ).decode("utf-8")
        return f"SharedKey {self.workspace_id}:{signature}"

    def ship(self, log_type: str, records: list[dict]) -> bool:
        """
        Send a batch of records to a custom table.
        log_type becomes the table name with _CL appended automatically.
        Returns True on success.
        """
        if not records:
            return True

        body         = json.dumps(records).encode("utf-8")
        rfc1123_date = datetime.now(timezone.utc).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        signature = self._build_signature(rfc1123_date, len(body))

        headers = {
            "Content-Type":  "application/json",
            "Log-Type":      log_type,
            "x-ms-date":     rfc1123_date,
            "Authorization": signature,
            # Tell LAW to use this field as the record timestamp
            "time-generated-field": "timestamp",
        }

        try:
            resp = httpx.post(self.base_url, content=body, headers=headers, timeout=30.0)
            if resp.status_code == 200:
                return True
            print(f"  ⚠  LAW API returned {resp.status_code}: {resp.text[:200]}")
            return False
        except Exception as e:
            print(f"  ✗  HTTP error: {e}")
            return False


# ---------------------------------------------------------------------------
#  Config loader
# ---------------------------------------------------------------------------

def load_config(args) -> tuple[str, str]:
    """Return (workspace_id, workspace_key) from args or deploy-outputs.json."""

    if args.workspace_id and args.workspace_key:
        return args.workspace_id, args.workspace_key

    outputs_file = Path(__file__).parent.parent / "infra" / "deploy-outputs.json"
    if not outputs_file.exists():
        print("ERROR: deploy-outputs.json not found.")
        print("  Either copy it from the deployment step, or pass")
        print("  --workspace-id and --workspace-key explicitly.")
        sys.exit(1)

    data = json.loads(outputs_file.read_text())

    def extract(key):
        # Handles both raw value and {"value": "..."} shape
        v = data.get(key, {})
        return v.get("value", v) if isinstance(v, dict) else v

    workspace_id  = extract("lawWorkspaceId")
    workspace_key = extract("lawPrimaryKey")

    if not workspace_id or not workspace_key:
        print("ERROR: Could not find lawWorkspaceId or lawPrimaryKey in deploy-outputs.json.")
        sys.exit(1)

    return workspace_id, workspace_key


# ---------------------------------------------------------------------------
#  Mode 1 — Ship PyRIT results (batch, one-shot)
# ---------------------------------------------------------------------------

def ship_pyrit_results(shipper: LogAnalyticsShipper):
    results_file = Path("results/redteam_results.json")
    if not results_file.exists():
        print("ERROR: results/redteam_results.json not found.")
        print("  Run pyrit_redteam.py first.")
        sys.exit(1)

    run_data = json.loads(results_file.read_text())
    results  = run_data.get("results", [])

    print(f"\n==> Shipping PyRIT results to Log Analytics...")
    print(f"    Table    : PyRITResults_CL")
    print(f"    Records  : {len(results)}")
    print(f"    Run time : {run_data.get('run_timestamp', 'unknown')}")

    # Flatten each result into a clean LAW record
    records = []
    for r in results:
        records.append({
            "timestamp":      r.get("timestamp"),
            "run_timestamp":  run_data.get("run_timestamp"),
            "category":       r.get("category"),
            "attack_name":    r.get("name"),
            "outcome":        r.get("outcome"),          # PASS/FAIL/INTERESTING/ERROR
            "expect_blocked": r.get("expect_blocked"),
            "blocked":        r.get("blocked"),
            "decision":       r.get("decision"),
            "score":          r.get("score"),
            "latency_ms":     r.get("latency_ms"),
            "prompt_preview": r.get("prompt", "")[:200],
            "reply_preview":  r.get("reply", "")[:200],
            "request_id":     r.get("request_id"),
            # Summary stats on every row — makes LAW queries easier
            "run_total":      run_data.get("total"),
            "run_pass_rate":  run_data.get("pass_rate"),
        })

    ok = shipper.ship("PyRITResults", records)
    if ok:
        print(f"  ✓  {len(records)} records shipped to PyRITResults_CL")
        print(f"     Allow up to 5 minutes for records to appear in LAW.")
    else:
        print(f"  ✗  Failed to ship PyRIT results.")
        sys.exit(1)


# ---------------------------------------------------------------------------
#  Mode 2 — Stream live LlamaFirewall events from the VM
# ---------------------------------------------------------------------------

def stream_live_events(shipper: LogAnalyticsShipper, vm_host: str):
    """
    SSHes to the VM and tails journalctl, parsing structured JSON log lines
    and shipping them to LlamaFirewallEvents_CL in batches.
    """

    print(f"\n==> Streaming live events from {vm_host}")
    print(f"    Table  : LlamaFirewallEvents_CL")
    print(f"    Press Ctrl+C to stop.\n")

    # journalctl -f streams new entries as they arrive
    cmd = [
        "ssh", "-o", "StrictHostKeyChecking=accept-new",
        vm_host,
        "journalctl -u llamafirewall -f -o cat --no-pager",
    ]

    batch      = []
    batch_size = 10      # Ship every N events
    last_ship  = time.monotonic()
    ship_every = 30.0    # Or every 30 seconds, whichever comes first
    total      = 0

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        for raw_line in proc.stdout:
            line = raw_line.strip()
            if not line:
                continue

            # Only process lines that are valid JSON security events
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Only ship security_event records (skip startup messages)
            if record.get("message") != "security_event":
                continue

            # Flatten to a clean LAW record
            law_record = {
                "timestamp":      record.get("timestamp"),
                "event_type":     record.get("event_type"),
                "request_id":     record.get("request_id"),
                "user_id":         record.get("user_id", ""),
                "source":          record.get("source", "user_input"),
                "blocked":        record.get("blocked"),
                "scan_decision":  record.get("scan_decision"),
                "scan_score":     record.get("scan_score"),
                "prompt_length":  record.get("prompt_length"),
                "prompt_preview": record.get("prompt_preview"),
                "response_length":record.get("response_length"),
                "latency_ms":     record.get("latency_ms"),
            }

            batch.append(law_record)
            total += 1

            elapsed = time.monotonic() - last_ship
            if len(batch) >= batch_size or elapsed >= ship_every:
                ok = shipper.ship("LlamaFirewallEvents", batch)
                status = "✓" if ok else "✗"
                print(f"  {status}  Shipped batch of {len(batch)} events  "
                      f"(total: {total})  "
                      f"[{datetime.now().strftime('%H:%M:%S')}]")
                batch     = []
                last_ship = time.monotonic()

    except KeyboardInterrupt:
        print("\n\n==> Stopped by user.")
        if batch:
            print(f"    Shipping final batch of {len(batch)} events...")
            shipper.ship("LlamaFirewallEvents", batch)
        print(f"    Total events shipped: {total}")

    finally:
        try:
            proc.terminate()
        except Exception:
            pass


# ---------------------------------------------------------------------------
#  Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ship PyRIT + LlamaFirewall logs to Azure Log Analytics"
    )
    parser.add_argument(
        "--mode",
        choices=["pyrit", "live", "both"],
        default="pyrit",
        help="pyrit=batch upload results | live=stream VM events | both=pyrit then live",
    )
    parser.add_argument(
        "--vm-host",
        default="azureuser@llamapoc-llama.eastus.cloudapp.azure.com",
        help="SSH target for live mode (user@hostname)",
    )
    parser.add_argument(
        "--workspace-id",
        default=None,
        help=(
            "Log Analytics Workspace ID. Overrides deploy-outputs.json. "
            "Use this to target your corporate Sentinel LAW instead of the PoC workspace. "
            "Find it: Azure Portal → Log Analytics → your workspace → Overview → Workspace ID"
        )
    )
    parser.add_argument(
        "--workspace-key",
        default=None,
        help=(
            "Log Analytics primary key. Overrides deploy-outputs.json. "
            "Find it: Azure Portal → Log Analytics → your workspace → Agents → Primary key"
        )
    )
    args = parser.parse_args()

    if args.mode in ("live", "both") and not args.vm_host:
        print("ERROR: --vm-host is required for live mode.")
        sys.exit(1)

    workspace_id, workspace_key = load_config(args)
    shipper = LogAnalyticsShipper(workspace_id, workspace_key)

    # Show where credentials came from
    source = "CLI flags" if (args.workspace_id and args.workspace_key) else "deploy-outputs.json"
    print(f"\n  Workspace : {workspace_id[:8]}...  (from {source})")

    if args.mode in ("pyrit", "both"):
        ship_pyrit_results(shipper)

    if args.mode in ("live", "both"):
        stream_live_events(shipper, args.vm_host)
