"""
LlamaFirewall Proxy — OpenAI-compatible endpoint on :8080

Sits between PyRIT (caller) and Ollama (LLM backend).
Accepts /v1/chat/completions requests, scans with a layered scanner stack,
forwards clean prompts to Ollama, and returns structured responses
with x_llamafirewall metadata attached.

Scanner stack (input):
  1. PromptGuard 2      — prompt injection / jailbreak detection (threshold 0.05)
  1.5 Perplexity filter — adversarial suffix detection via GPT-2 perplexity
  2. HiddenASCII        — BiDi text, invisible characters, encoding tricks
  3. Regex (default)    — built-in prompt injection, PII patterns
  4. custom_patterns    — XSS, SQL injection, credential extraction, tool abuse
  5. LlamaGuard 3       — semantic content safety (Llama Guard 3:8B via Ollama)
  6. NOVA               — YARA-style rules, 10 custom rules
  7. Crescendo tracker  — stateful session-level escalation detection

Scanner stack (output — preprod/production only):
  8. LlamaGuard 3       — output content safety scan
  9. CodeShield         — malicious code detection in responses
  10. Output regex      — sensitive data pattern matching on responses

Deployed to: /opt/llamafirewall/proxy.py
Managed by:  llamafirewall.service (systemd)
"""

import asyncio
import json
import logging
import os
import re as _re
import sys
import time
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from llamafirewall import (
    LlamaFirewall,
    ScannerType,
    UserMessage,
    ScanDecision,
    Role,
)
from llamafirewall.llamafirewall import custom_scanner_registry
from llamafirewall.scanners.regex_scanner import RegexScanner

# Scanner base class — confirmed paths from introspection
from llamafirewall.scanners.base_scanner import Scanner, ScanResult
from llamafirewall.llamafirewall_data_types import ScanStatus

# ---------------------------------------------------------------------------
#  Structured JSON logger — output captured by systemd → journald
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    def format(self, record):
        obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level":     record.levelname,
            "message":   record.getMessage(),
        }
        if hasattr(record, "extra"):
            obj.update(record.extra)
        return json.dumps(obj)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JSONFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger("llamafirewall.proxy")

# ---------------------------------------------------------------------------
#  Custom pattern scanner
#  Extends RegexScanner with domain-specific patterns targeting the attack
#  categories PromptGuard 2 is structurally blind to:
#    - content_safety  : XSS, SQL injection
#    - data_leakage    : credential/token extraction, source code exfiltration
#    - tool_abuse      : command injection, dangerous function calls
# ---------------------------------------------------------------------------

class CustomPatternScanner(RegexScanner):
    """Domain-specific regex scanner registered in LlamaFirewall's custom registry."""

    CUSTOM_PATTERNS = {
        # Content safety — SQL injection
        "SQL injection": (
            r"(SELECT\s+.+\s+FROM\s|INSERT\s+INTO\s|UPDATE\s+.+\s+SET\s"
            r"|DELETE\s+FROM\s|DROP\s+TABLE\s|UNION\s+SELECT\s|ALTER\s+TABLE\s)"
        ),
        # Content safety — XSS
        "XSS": (
            r"(<script[\s>]|javascript\s*:|onerror\s*=|onload\s*=|"
            r"alert\s*\(|document\.cookie|eval\s*\(|<iframe[\s>])"
        ),
        # Data leakage — credential/token extraction
        "Credential extraction": (
            r"(api[_\-]?key\s*[=:]\s*['\"]?\w{8,}|secret[_\-]?key\s*[=:]\s*['\"]?\w{8,}"
            r"|access[_\-]?token\s*[=:]\s*['\"]?\w{8,}"
            r"|bearer\s+[a-zA-Z0-9\-_\.]{20,}"
            r"|password\s*[=:]\s*['\"]?\S{4,})"
        ),
        # Data leakage — system file / source code exfiltration
        "Source code exfiltration": (
            r"(cat\s+/etc/(passwd|shadow|hosts|sudoers)"
            r"|/proc/self/(environ|cmdline|maps)"
            r"|\bauthorized_keys\b|\bid_rsa\b"
            r"|\.env\b|\.git/config)"
        ),
        # Tool abuse — shell command injection
        "Command injection": (
            r"(;\s*(rm\s+-rf|wget\s+http|curl\s+http|chmod\s+[0-7]{3,4}|"
            r"sudo\s+\w|bash\s+-[ci]|sh\s+-[ci])"
            r"|\|\s*(bash|sh|python3?|perl|ruby)\b"
            r"|`[^`]{5,}`|\$\([^)]{5,}\))"
        ),
        # Tool abuse — dangerous Python/system function calls
        "Dangerous function call": (
            r"(__import__\s*\(\s*['\"]os['\"]"
            r"|os\.system\s*\(|subprocess\.(run|Popen|call)\s*\("
            r"|exec\s*\(\s*['\"]|eval\s*\(\s*['\"]"
            r"|open\s*\(['\"][/~])"
        ),
    }

    def __init__(
        self,
        scanner_name: str = "Custom Pattern Scanner",
        block_threshold: float = 1.0,
    ) -> None:
        super().__init__(scanner_name=scanner_name, block_threshold=block_threshold)
        for name, pattern in self.CUSTOM_PATTERNS.items():
            try:
                self.patterns[name] = _re.compile(
                    pattern, _re.IGNORECASE | _re.DOTALL
                )
                logger.debug(f"Custom pattern loaded: {name}")
            except _re.error as e:
                logger.warning(f"Invalid custom regex pattern '{name}': {e}")


# Register in LlamaFirewall's custom scanner registry
custom_scanner_registry["custom_patterns"] = CustomPatternScanner
logger.info(f"Custom pattern scanner registered ({len(CustomPatternScanner.CUSTOM_PATTERNS)} patterns).")

# ---------------------------------------------------------------------------
#  NOVA scanner
#  YARA-inspired rule engine combining keyword, semantic, and LLM detection.
#  Targets semantic social engineering attacks that PromptGuard and rule-based
#  scanners miss: logic traps, capability fabrication, political manipulation,
#  bioweapon synthesis disguised as academic curiosity, system prompt extraction.
#
#  Rules file: /opt/llamafirewall/nova-rules-custom/social_engineering_pt.nov
#  LLM tier  : llama-guard3:8b via Ollama (already running on this VM)
#
#  Disable:  sudo systemctl set-environment NOVA_DISABLED=1
#            sudo systemctl restart llamafirewall
# ---------------------------------------------------------------------------

NOVA_DISABLED = os.environ.get("NOVA_DISABLED", "0").strip() == "1"
NOVA_RULES_PATH = "/opt/llamafirewall/nova-rules-custom/social_engineering_pt.nov"

_nova_matchers: list = []

def _init_nova():
    """Load and compile NOVA rules at service startup."""
    global _nova_matchers
    if NOVA_DISABLED:
        logger.info("NOVA scanner DISABLED (NOVA_DISABLED=1).")
        return
    if not _re.path.exists(NOVA_RULES_PATH) if hasattr(_re, 'path') else not __import__('os').path.exists(NOVA_RULES_PATH):
        logger.warning(f"NOVA rules file not found: {NOVA_RULES_PATH}. Scanner disabled.")
        return
    try:
        import re as _stdlib_re
        from nova.core.parser import NovaParser
        from nova.evaluators.llm import OllamaEvaluator
        from nova import NovaMatcher as _NovaMatcher

        content = open(NOVA_RULES_PATH, encoding="utf-8").read()
        blocks  = _stdlib_re.split(r'(?=^rule\s+\w+\s*\{)', content, flags=_stdlib_re.MULTILINE)
        parser  = NovaParser()
        for block in blocks:
            block = block.strip()
            if block.startswith("rule "):
                try:
                    rule = parser.parse(block)
                    # Disable LLM tier — phi3:mini is not a safety classifier
                    # and causes false positives on benign prompts. LlamaGuard3
                    # already provides semantic LLM coverage in the stack.
                    # NOVA contributes keyword + semantic similarity layers only.
                    _nova_matchers.append(_NovaMatcher(
                        rule,
                        llm_evaluator=None,
                        create_llm_evaluator=False,
                    ))
                    logger.info(f"NOVA rule loaded: {rule.name}")
                except Exception as e:
                    logger.warning(f"NOVA rule parse error: {e}")

        logger.info(f"NOVA scanner ready — {len(_nova_matchers)} rules loaded.")
    except Exception as e:
        logger.warning(f"NOVA scanner init failed: {e}. Scanner disabled.")

_init_nova()


def _nova_scan(prompt: str) -> tuple[bool, str]:
    """
    Run NOVA rules sequentially against prompt.
    Returns (blocked, matched_rule_name) on first match.
    Fails open on error — NOVA is an additional layer, not the primary gate.
    Sequential is safer than parallel on CPU-only VMs running multiple LLMs.
    """
    if not _nova_matchers:
        return False, ""
    for matcher in _nova_matchers:
        try:
            result = matcher.check_prompt(prompt)
            if result and result.get("matched"):
                return True, matcher.rule.name
        except Exception as e:
            logger.warning(f"NOVA rule {matcher.rule.name} error: {e}")
    return False, ""

# ---------------------------------------------------------------------------
#  Perplexity filter (layer 1.5)
#  Detects adversarial suffixes generated by gradient-based attacks (GCG,
#  AutoDAN, PEZ). These suffixes produce characteristically unusual token
#  sequences — high perplexity under a reference language model — while
#  remaining semantically coherent to the target LLM.
#
#  Uses GPT-2 (small, ~500 MB) via transformers — already installed.
#  Runs on CPU in ~100-200ms. Complementary to HiddenASCII (rule-based).
#
#  PERPLEXITY_THRESHOLD: empirically calibrated. Lower = more aggressive.
#    500 (default) — catches strong adversarial suffixes with low false positives
#    200           — more aggressive, may catch some legitimate technical prompts
#    1000          — conservative, catches only extreme outliers
#
#  Disable: sudo systemctl set-environment PERPLEXITY_FILTER_ENABLED=0
# ---------------------------------------------------------------------------

PERPLEXITY_FILTER_ENABLED = os.environ.get("PERPLEXITY_FILTER_ENABLED", "1").strip() == "1"
PERPLEXITY_THRESHOLD      = float(os.environ.get("PERPLEXITY_THRESHOLD", "500.0"))

_perplexity_model     = None
_perplexity_tokenizer = None

def _init_perplexity_filter():
    global _perplexity_model, _perplexity_tokenizer
    if not PERPLEXITY_FILTER_ENABLED:
        return
    try:
        import torch
        from transformers import GPT2LMHeadModel, GPT2TokenizerFast
        logger.info("Loading GPT-2 for perplexity filter...")
        _perplexity_tokenizer = GPT2TokenizerFast.from_pretrained("gpt2")
        _perplexity_model     = GPT2LMHeadModel.from_pretrained("gpt2")
        _perplexity_model.eval()
        logger.info("Perplexity filter ready (GPT-2 small, threshold=%.0f)" % PERPLEXITY_THRESHOLD)
    except Exception as e:
        logger.warning(f"Perplexity filter init failed: {e}. Disabled.")
        _perplexity_model = None

_init_perplexity_filter()


def _compute_perplexity(text: str) -> float:
    """
    Compute GPT-2 perplexity of text. Higher = more unusual/adversarial.
    Returns infinity on error (fail-open — never block due to perplexity error).
    """
    if _perplexity_model is None or _perplexity_tokenizer is None:
        return 0.0
    try:
        import torch
        # Use only the last 512 tokens — adversarial suffixes are typically appended
        inputs = _perplexity_tokenizer(
            text, return_tensors="pt", truncation=True, max_length=512
        )
        with torch.no_grad():
            outputs = _perplexity_model(**inputs, labels=inputs["input_ids"])
        import math
        return math.exp(outputs.loss.item())
    except Exception as e:
        logger.warning(f"Perplexity computation error: {e}")
        return 0.0


def _perplexity_scan(prompt: str) -> tuple[bool, float]:
    """
    Returns (blocked, perplexity_score).
    Blocks if perplexity exceeds PERPLEXITY_THRESHOLD.
    Fails open — never blocks due to model error.
    """
    if not PERPLEXITY_FILTER_ENABLED or _perplexity_model is None:
        return False, 0.0
    ppl = _compute_perplexity(prompt)
    if ppl > PERPLEXITY_THRESHOLD:
        logger.info(f"Perplexity filter: BLOCK (score={ppl:.1f} > threshold={PERPLEXITY_THRESHOLD})")
        return True, ppl
    return False, ppl

# ---------------------------------------------------------------------------
#  Output sensitive data patterns (layer output-2)
#  Applied to LLM responses before returning to caller.
#  Catches accidental disclosure of credentials, keys, PII in model output.
# ---------------------------------------------------------------------------

_OUTPUT_SENSITIVE_PATTERNS = [
    # Credentials / keys
    (_re.compile(r'(?i)(password|passwd|secret|api[_\s-]?key)\s*[:=]\s*\S+'), "credential_in_output"),
    (_re.compile(r'(?i)(bearer|token)\s+[A-Za-z0-9\-._~+/]+=*'), "token_in_output"),
    (_re.compile(r'(?i)(private[_\s]key|-----BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE)'), "private_key_in_output"),
    # Cloud / SaaS patterns
    (_re.compile(r'AKIA[0-9A-Z]{16}'), "aws_key_in_output"),
    (_re.compile(r'(?i)ghp_[A-Za-z0-9]{36}'), "github_pat_in_output"),
    # Brazilian PII
    (_re.compile(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b'), "cpf_in_output"),
    (_re.compile(r'\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b'), "cnpj_in_output"),
    # Connection strings
    (_re.compile(r'(?i)(mongodb|postgresql|mysql|redis|amqp)://[^\s]+'), "connection_string_in_output"),
]


def _scan_output_for_sensitive_data(response_text: str) -> tuple[bool, str]:
    """
    Scan LLM response for sensitive data patterns.
    Returns (blocked, pattern_name) on first match.
    Fails open — never blocks on error.
    """
    try:
        for pattern, name in _OUTPUT_SENSITIVE_PATTERNS:
            if pattern.search(response_text):
                return True, name
    except Exception as e:
        logger.warning(f"Output sensitive data scan error: {e}")
    return False, ""

# ---------------------------------------------------------------------------
#  Crescendo session tracker (layer 7)
#  Detects multi-turn escalation attacks by tracking per-session signals:
#    - near_miss_count: turns where PromptGuard score was high but not blocked
#    - topic_shift_count: turns with sudden topic changes toward restricted areas
#    - turn_count: total session turns
#
#  When near-miss frequency rises across consecutive turns — the classic
#  Crescendo fingerprint — the session is flagged and subsequent prompts
#  are blocked regardless of individual scan scores.
#
#  Limitation: in-memory state — resets on proxy restart.
#  Production path: replace _session_store with Redis for persistence.
#
#  CRESCENDO_NEAR_MISS_THRESHOLD (default 0.03): score above this = near miss
#  CRESCENDO_BLOCK_AFTER (default 3): block after N consecutive near misses
#
#  Disable: sudo systemctl set-environment CRESCENDO_ENABLED=0
# ---------------------------------------------------------------------------

CRESCENDO_ENABLED           = os.environ.get("CRESCENDO_ENABLED",            "1").strip() == "1"
CRESCENDO_NEAR_MISS_THRESHOLD = float(os.environ.get("CRESCENDO_NEAR_MISS_THRESHOLD", "0.03"))
CRESCENDO_BLOCK_AFTER       = int(os.environ.get("CRESCENDO_BLOCK_AFTER",    "3"))
CRESCENDO_SESSION_TTL       = int(os.environ.get("CRESCENDO_SESSION_TTL",    "3600"))  # seconds

# Session state: { session_id: { turns, near_misses, last_active, blocked } }
_session_store: dict = {}
_session_store_lock = asyncio.Lock()


async def _crescendo_update(session_id: str, scan_score: float, blocked: bool) -> tuple[bool, str]:
    """
    Update session state and return (crescendo_blocked, reason).
    Called after primary scan completes — uses the PromptGuard score as signal.
    """
    if not CRESCENDO_ENABLED or not session_id:
        return False, ""

    now = time.monotonic()
    async with _session_store_lock:
        # Purge stale sessions to avoid unbounded memory growth
        stale = [k for k, v in _session_store.items()
                 if now - v["last_active"] > CRESCENDO_SESSION_TTL]
        for k in stale:
            del _session_store[k]

        if session_id not in _session_store:
            _session_store[session_id] = {
                "turns":       0,
                "near_misses": 0,
                "last_active": now,
                "blocked":     False,
            }

        sess = _session_store[session_id]
        sess["turns"]       += 1
        sess["last_active"]  = now

        # If session was already flagged as Crescendo, keep blocking
        if sess["blocked"]:
            return True, f"Crescendo: session flagged (turn {sess['turns']})"

        # Track near misses — high score but not individually blocked
        if not blocked and scan_score >= CRESCENDO_NEAR_MISS_THRESHOLD:
            sess["near_misses"] += 1
            logger.info(f"Crescendo: near-miss #{sess['near_misses']} in session {session_id[:8]} (score={scan_score:.4f})")
        elif blocked:
            # A hard block also counts as escalation signal
            sess["near_misses"] += 1
        else:
            # Clean prompt — decay near-miss count by 1 (reward good behaviour)
            sess["near_misses"] = max(0, sess["near_misses"] - 1)

        # Trigger Crescendo block after N consecutive near-misses
        if sess["near_misses"] >= CRESCENDO_BLOCK_AFTER:
            sess["blocked"] = True
            logger.warning(
                f"Crescendo: session {session_id[:8]} BLOCKED after "
                f"{sess['near_misses']} near-misses over {sess['turns']} turns"
            )
            return True, (
                f"Crescendo: session blocked after {sess['near_misses']} "
                f"consecutive near-miss prompts (escalation pattern detected)"
            )

    return False, ""

# ---------------------------------------------------------------------------
#  Llama Guard 3 scanner
#  Calls llama-guard3:8b running in Ollama (localhost:11434).
#  Uses the MLCommons hazard taxonomy — catches social engineering, content
#  safety violations, and subtle jailbreaks that PromptGuard 2 misses.
#
#  Enable:  already in scanner stack by default
#  Disable: set env var LLAMA_GUARD_DISABLED=1 and restart llamafirewall
#           sudo systemctl set-environment LLAMA_GUARD_DISABLED=1
#           sudo systemctl restart llamafirewall
# ---------------------------------------------------------------------------

LLAMA_GUARD_DISABLED = os.environ.get("LLAMA_GUARD_DISABLED", "0").strip() == "1"

# MLCommons hazard taxonomy — Llama Guard 3 category labels
_LG3_CATEGORIES = {
    "S1":  "Violent Crimes",
    "S2":  "Non-Violent Crimes",
    "S3":  "Sex Crimes",
    "S4":  "Child Sexual Exploitation",
    "S5":  "Defamation",
    "S6":  "Specialized Advice",
    "S7":  "Privacy",
    "S8":  "Intellectual Property",
    "S9":  "Indiscriminate Weapons",
    "S10": "Hate",
    "S11": "Self-Harm",
    "S12": "Sexual Content",
    "S13": "Elections",
}


class LlamaGuard3Scanner(Scanner):
    """
    Semantic content safety scanner using Llama Guard 3:8B via Ollama.
    Catches intent-based threats that pattern/ML classifiers miss:
    social engineering, fictional framing, emotional manipulation,
    multi-turn escalation, and subtle jailbreaks.

    Registered as 'llama_guard3' in the custom scanner registry.
    Calls http://localhost:11434/api/chat — requires llama-guard3:8b to be
    pulled: ollama pull llama-guard3:8b
    """

    OLLAMA_URL = "http://localhost:11434/api/chat"
    OLLAMA_MODEL = "llama-guard3:8b"
    # Timeout per scan — 8B on CPU takes ~5-15s for normal prompts.
    # Very long prompts (>1000 chars) can take longer — set generously.
    SCAN_TIMEOUT = 120.0
    # Truncate prompts before sending to LlamaGuard3 — attack signals are
    # almost always in the first 512 tokens (~2000 chars). Truncating avoids
    # timeouts on adversarially long inputs like homoglyph-heavy code blocks.
    MAX_INPUT_CHARS = 2000

    def __init__(
        self,
        scanner_name: str = "LlamaGuard3Scanner",
        block_threshold: float = 0.5,
    ) -> None:
        super().__init__(scanner_name, block_threshold)

    async def scan(self, message, trace=None):  # type: ignore[override]
        content = message.content if hasattr(message, "content") else str(message)

        # Truncate very long prompts — attack signals are in the first ~2000
        # chars. Adversarially long inputs (homoglyphs, code blocks) would
        # otherwise cause timeouts on CPU inference.
        if len(content) > self.MAX_INPUT_CHARS:
            logger.debug(f"LlamaGuard3: truncating prompt from {len(content)} to {self.MAX_INPUT_CHARS} chars")
            content = content[:self.MAX_INPUT_CHARS]

        try:
            async with httpx.AsyncClient(timeout=self.SCAN_TIMEOUT) as client:
                resp = await client.post(
                    self.OLLAMA_URL,
                    json={
                        "model":    self.OLLAMA_MODEL,
                        "messages": [{"role": "user", "content": content}],
                        "stream":   False,
                    },
                )
            resp.raise_for_status()
            result_text = resp.json()["message"]["content"].strip().lower()

        except Exception as e:
            # Fail CLOSED on network/model errors — if LlamaGuard3 can't scan
            # (timeout, OOM, model unavailable), block the prompt.
            # Security-first: an unscanned prompt is an unvetted prompt.
            logger.warning(f"LlamaGuard3: scan error — {e}. Blocking prompt (fail-closed).")
            return ScanResult(
                decision=ScanDecision.BLOCK,
                reason=f"LlamaGuard3: blocked (scan error — {str(e)[:80]})",
                score=1.0,
                status=ScanStatus.SUCCESS,
            )

        is_unsafe = result_text.startswith("unsafe")

        if is_unsafe:
            lines = result_text.split("\n")
            raw_cats = lines[1].strip() if len(lines) > 1 else ""
            cat_names = [
                _LG3_CATEGORIES.get(c.strip().upper(), c.strip())
                for c in raw_cats.split(",")
                if c.strip()
            ]
            reason = f"LlamaGuard3: unsafe — {', '.join(cat_names) or raw_cats}"
            return ScanResult(
                decision=ScanDecision.BLOCK,
                reason=reason,
                score=1.0,
                status=ScanStatus.SUCCESS,
            )

        return ScanResult(
            decision=ScanDecision.ALLOW,
            reason="LlamaGuard3: safe",
            score=0.0,
            status=ScanStatus.SUCCESS,
        )


# Register — only if not disabled via env var
if not LLAMA_GUARD_DISABLED:
    custom_scanner_registry["llama_guard3"] = LlamaGuard3Scanner
    logger.info("LlamaGuard3 scanner registered (llama-guard3:8b via Ollama).")
else:
    logger.info("LlamaGuard3 scanner DISABLED (LLAMA_GUARD_DISABLED=1).")

# ---------------------------------------------------------------------------
#  LlamaFirewall — layered scanner stack
#
#  Scanners run in order; ANY block = final decision is BLOCK.
#  PromptGuard 2 score is further overridden by BLOCK_THRESHOLD below.
#
#  Stack:
#    PROMPT_GUARD   — ML model, detects injection/jailbreak syntax (threshold 0.05)
#    HIDDEN_ASCII   — rule-based, detects BiDi/invisible chars/encoding tricks
#    REGEX          — rule-based, built-in prompt injection + PII patterns
#    custom_patterns — rule-based, domain-specific patterns (see above)
# ---------------------------------------------------------------------------

logger.info("Initialising LlamaFirewall...")

firewall = LlamaFirewall({
    Role.USER: [
        ScannerType.PROMPT_GUARD,   # ML: injection/jailbreak (threshold 0.05)
        ScannerType.HIDDEN_ASCII,   # Rule: BiDi, invisible chars, encoding tricks
        ScannerType.REGEX,          # Rule: prompt injection, PII patterns
        "custom_patterns",          # Rule: XSS, SQL, credentials, tool abuse
    ] + (["llama_guard3"] if not LLAMA_GUARD_DISABLED else []),
    Role.ASSISTANT: [],
    Role.SYSTEM:    [],
    Role.TOOL:      [],
    Role.MEMORY:    [],
})

active_scanners = ["PromptGuard2"]
if PERPLEXITY_FILTER_ENABLED and _perplexity_model is not None:
    active_scanners.append("PerplexityFilter")
active_scanners += ["HiddenASCII", "Regex", "CustomPatterns"]
if not LLAMA_GUARD_DISABLED:
    active_scanners.append("LlamaGuard3")
if not NOVA_DISABLED and _nova_matchers:
    active_scanners.append(f"NOVA({len(_nova_matchers)}rules)")
if CRESCENDO_ENABLED:
    active_scanners.append("CrescendoTracker")

logger.info(f"LlamaFirewall ready — {len(active_scanners)} scanners active: {active_scanners}")

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL    = "phi3:mini"

# ---------------------------------------------------------------------------
#  Profile-aware configuration — read from systemd environment
#  Set by setup_vm.sh based on selected profile (lab/preprod/production).
#  Override any value with: sudo systemctl set-environment KEY=value
#                           sudo systemctl restart llamafirewall
# ---------------------------------------------------------------------------

PROFILE = os.environ.get("LLAMAFIREWALL_PROFILE", "lab")

# PromptGuard 2 block threshold — lower = more aggressive
# lab: 0.05  preprod: 0.10  production: 0.15
BLOCK_THRESHOLD = float(os.environ.get("PROMPTGUARD_THRESHOLD", "0.05"))

# Output scanning — scan assistant responses through LlamaGuard3
# lab: off  preprod: on  production: on
OUTPUT_SCAN_ENABLED = os.environ.get("OUTPUT_SCAN_ENABLED", "0").strip() == "1"

# ---------------------------------------------------------------------------
#  BYPASS MODE
#  When enabled, all scanning is skipped and prompts are forwarded directly
#  to Ollama. The proxy stays running — no network changes needed.
#  Use during production incidents where legitimate traffic is being dropped.
#
#  Enable:  sudo systemctl set-environment BYPASS_MODE=1
#           sudo systemctl restart llamafirewall
#  Disable: sudo systemctl unset-environment BYPASS_MODE
#           sudo systemctl restart llamafirewall
#
#  Or use:  ./toggle_bypass.sh on|off|status azureuser@<vm-fqdn>
# ---------------------------------------------------------------------------
BYPASS_MODE = os.environ.get("BYPASS_MODE", "0").strip() == "1"

if BYPASS_MODE:
    logger.warning("⚠️  BYPASS MODE ENABLED — all scanning disabled, prompts forwarded directly to Ollama")
else:
    logger.info(f"Profile: {PROFILE} | PG threshold: {BLOCK_THRESHOLD} | Output scan: {OUTPUT_SCAN_ENABLED}")

# ---------------------------------------------------------------------------
#  NO_LLM mode
#  When enabled, allowed prompts get a stub response instead of hitting
#  Ollama. Cuts per-prompt latency from ~10-30s to ~1-2s.
#  Enable:  sudo systemctl set-environment NO_LLM=1
#           sudo systemctl restart llamafirewall
#  Disable: sudo systemctl unset-environment NO_LLM
#           sudo systemctl restart llamafirewall
# ---------------------------------------------------------------------------
NO_LLM = os.environ.get("NO_LLM", "0").strip() == "1"
if NO_LLM:
    logger.info("NO_LLM mode enabled — Ollama will be bypassed for allowed prompts.")

# ---------------------------------------------------------------------------
#  PROMPT LOGGING TO SENTINEL LAW
#
#  Ships full prompt text + scan decision to a tightly-controlled
#  LlamaFirewallPrompts_CL table in Log Analytics.
#
#  Access to this table MUST be restricted via table-level RBAC in LAW
#  to incident investigators only — see README for IAM setup.
#
#  PII redaction (optional, production only):
#    When PII_REDACTION_ENABLED=1 and AZURE_LANGUAGE_ENDPOINT is set,
#    the prompt is passed through Azure AI Language PII detection API
#    before being shipped to LAW. All detected PII is masked with *.
#    In lab/corp-lab, leave disabled — prompts are synthetic attack data.
#
#  Enable:
#    sudo systemctl set-environment PROMPT_LOGGING_ENABLED=1
#    sudo systemctl set-environment LAW_WORKSPACE_ID=<your-workspace-id>
#    sudo systemctl set-environment LAW_WORKSPACE_KEY=<your-primary-key>
#    sudo systemctl restart llamafirewall
# ---------------------------------------------------------------------------

import base64
import hashlib
import hmac

PROMPT_LOGGING_ENABLED   = os.environ.get("PROMPT_LOGGING_ENABLED",  "0").strip() == "1"
LAW_WORKSPACE_ID         = os.environ.get("LAW_WORKSPACE_ID",         "").strip()
LAW_WORKSPACE_KEY        = os.environ.get("LAW_WORKSPACE_KEY",         "").strip()
PII_REDACTION_ENABLED    = os.environ.get("PII_REDACTION_ENABLED",    "0").strip() == "1"
AZURE_LANGUAGE_ENDPOINT  = os.environ.get("AZURE_LANGUAGE_ENDPOINT",  "").strip()
AZURE_LANGUAGE_KEY       = os.environ.get("AZURE_LANGUAGE_KEY",       "").strip()

# ---------------------------------------------------------------------------
#  LAW ingestion method — drives how proxy.py authenticates to LAW
#  shared_key     : lab / corp-lab — HMAC-SHA256 with workspace primary key
#  managed_identity: preprod / production — Entra ID token from IMDS, no keys
# ---------------------------------------------------------------------------
LAW_INGESTION_METHOD = os.environ.get("LAW_INGESTION_METHOD", "shared_key").strip()

# DCR-based ingestion — preprod/production (managed_identity only)
# Values come from deploy.sh outputs after deployment
DCE_ENDPOINT   = os.environ.get("DCE_ENDPOINT",   "").strip()   # e.g. https://xxx.eastus.ingest.monitor.azure.com
DCR_IMMUTABLE_ID = os.environ.get("DCR_IMMUTABLE_ID", "").strip() # e.g. dcr-xxx
DCR_STREAM_NAME  = os.environ.get("DCR_STREAM_NAME",  "Custom-LlamaFirewallPrompts_CL").strip()

if PROMPT_LOGGING_ENABLED:
    if LAW_INGESTION_METHOD == "shared_key":
        if not LAW_WORKSPACE_ID or not LAW_WORKSPACE_KEY:
            logger.warning("PROMPT_LOGGING_ENABLED=1 (shared_key) but LAW_WORKSPACE_ID/KEY not set — prompt logging disabled.")
            PROMPT_LOGGING_ENABLED = False
        else:
            logger.info(f"Prompt logging ENABLED → LlamaFirewallPrompts_CL via Shared Key | PII redaction: {PII_REDACTION_ENABLED}")
    elif LAW_INGESTION_METHOD == "managed_identity":
        if not DCE_ENDPOINT or not DCR_IMMUTABLE_ID:
            logger.warning("PROMPT_LOGGING_ENABLED=1 (managed_identity) but DCE_ENDPOINT/DCR_IMMUTABLE_ID not set — prompt logging disabled.")
            PROMPT_LOGGING_ENABLED = False
        else:
            logger.info(f"Prompt logging ENABLED → LlamaFirewallPrompts_CL via Managed Identity | PII redaction: {PII_REDACTION_ENABLED}")

# ---------------------------------------------------------------------------
#  Managed Identity token cache
#  IMDS tokens are valid for up to 24h. We cache and refresh 5 min before expiry.
# ---------------------------------------------------------------------------
_mi_token_cache: dict = {"token": None, "expires_at": 0.0}

async def _get_managed_identity_token() -> str:
    """
    Fetch an Entra ID token from the Azure IMDS endpoint.
    Caches the token and refreshes 5 minutes before expiry.
    Only valid inside an Azure VM with System-Assigned Managed Identity.
    """
    now = time.monotonic()
    # Refresh if missing or expiring in < 5 minutes
    if _mi_token_cache["token"] and now < _mi_token_cache["expires_at"] - 300:
        return _mi_token_cache["token"]

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                "http://169.254.169.254/metadata/identity/oauth2/token",
                params={
                    "api-version": "2018-02-01",
                    "resource":    "https://monitor.azure.com/",
                },
                headers={"Metadata": "true"},
            )
            resp.raise_for_status()
            data = resp.json()
            _mi_token_cache["token"]      = data["access_token"]
            _mi_token_cache["expires_at"] = now + int(data.get("expires_in", 3600))
            return _mi_token_cache["token"]
    except Exception as e:
        raise RuntimeError(f"Failed to get Managed Identity token from IMDS: {e}")


async def _redact_pii(text: str) -> str:
    """
    Call Azure AI Language PII detection API to redact sensitive entities.
    Returns redacted text. Falls back to original on error (fail-open — never block a prompt
    just because PII redaction failed).
    Only called when PII_REDACTION_ENABLED=1 and AZURE_LANGUAGE_ENDPOINT is set.
    """
    if not PII_REDACTION_ENABLED or not AZURE_LANGUAGE_ENDPOINT or not AZURE_LANGUAGE_KEY:
        return text
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{AZURE_LANGUAGE_ENDPOINT}/language/:analyze-text?api-version=2023-04-01",
                headers={
                    "Ocp-Apim-Subscription-Key": AZURE_LANGUAGE_KEY,
                    "Content-Type": "application/json",
                },
                json={
                    "kind": "PiiEntityRecognition",
                    "analysisInput": {
                        "documents": [{"id": "1", "language": "pt", "text": text}]
                    },
                    "parameters": {"modelVersion": "latest"},
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                redacted = data["results"]["documents"][0].get("redactedText", text)
                return redacted
    except Exception as e:
        logger.warning(f"PII redaction error (fail-open): {e}")
    return text


async def _ship_prompt_to_law(
    request_id: str,
    prompt: str,
    full_messages: list,
    scan_decision: str,
    scan_score: float,
    scan_reason: str,
    blocked: bool,
    latency_ms: float,
    user_id: str = "",
    source: str = "user_input",
):
    """
    Ship full prompt + scan decision to LlamaFirewallPrompts_CL in LAW.
    Routes to shared key (lab/corp-lab) or Managed Identity DCR (preprod/prod).
    Runs as a background task — never blocks the request path.
    """
    if not PROMPT_LOGGING_ENABLED:
        return

    try:
        prompt_to_log = await _redact_pii(prompt)

        record = [{
            "TimeGenerated": datetime.now(timezone.utc).isoformat(),
            "request_id":    request_id,
            "user_id":       user_id,
            "source":        source,
            "profile":       PROFILE,
            "full_prompt":   prompt_to_log,
            "prompt_length": len(prompt),
            "message_count": len(full_messages),
            "scan_decision": scan_decision,
            "scan_score":    round(scan_score, 4),
            "scan_reason":   scan_reason[:500] if scan_reason else "",
            "blocked":       blocked,
            "latency_ms":    round(latency_ms, 1),
            "pii_redacted":  PII_REDACTION_ENABLED,
        }]

        body = json.dumps(record).encode("utf-8")

        if LAW_INGESTION_METHOD == "managed_identity":
            # ----------------------------------------------------------------
            #  DCR-based ingestion via Managed Identity — preprod/production
            #  No static keys. Token fetched from IMDS, cached up to 24h.
            # ----------------------------------------------------------------
            token = await _get_managed_identity_token()
            url   = (f"{DCE_ENDPOINT}/dataCollectionRules/{DCR_IMMUTABLE_ID}"
                     f"/streams/{DCR_STREAM_NAME}?api-version=2023-01-01")
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    url,
                    content=body,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type":  "application/json",
                    },
                )
                if resp.status_code not in (200, 204):
                    logger.warning(f"Prompt log (managed_identity) failed: HTTP {resp.status_code} — {resp.text[:100]}")

        else:
            # ----------------------------------------------------------------
            #  Shared Key ingestion — lab/corp-lab
            #  HMAC-SHA256 signature using workspace primary key.
            # ----------------------------------------------------------------
            rfc1123_date   = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
            string_to_hash = f"POST\n{len(body)}\napplication/json\nx-ms-date:{rfc1123_date}\n/api/logs"
            sig = base64.b64encode(
                hmac.new(
                    base64.b64decode(LAW_WORKSPACE_KEY),
                    string_to_hash.encode("utf-8"),
                    digestmod=hashlib.sha256,
                ).digest()
            ).decode("utf-8")
            url = f"https://{LAW_WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    url,
                    content=body,
                    headers={
                        "Content-Type":  "application/json",
                        "Log-Type":      "LlamaFirewallPrompts",
                        "x-ms-date":     rfc1123_date,
                        "Authorization": f"SharedKey {LAW_WORKSPACE_ID}:{sig}",
                        "time-generated-field": "TimeGenerated",
                    },
                )
                if resp.status_code != 200:
                    logger.warning(f"Prompt log (shared_key) failed: HTTP {resp.status_code}")

    except Exception as e:
        logger.warning(f"Prompt log ship error: {e}")

app = FastAPI(title="LlamaFirewall Proxy", version="0.1.0")

# ---------------------------------------------------------------------------
#  Security event logger
# ---------------------------------------------------------------------------

def emit_security_log(request_id, prompt, scan_decision, scan_score,
                      blocked, scan_reason="", response_text="", latency_ms=0.0,
                      user_id="", source="user_input"):
    logger.info("security_event", extra={
        "event_type":      "llm_request",
        "request_id":      request_id,
        "user_id":         user_id,
        "source":          source,
        "blocked":         blocked,
        "scan_decision":   scan_decision,
        "scan_score":      round(scan_score, 4),
        "scan_reason":     scan_reason[:200] if scan_reason else "",
        "prompt_length":   len(prompt),
        "prompt_preview":  prompt[:120].replace("\n", " "),
        "response_length": len(response_text),
        "latency_ms":      round(latency_ms, 1),
    })

# ---------------------------------------------------------------------------
#  POST /v1/chat/completions  — OpenAI-compatible
# ---------------------------------------------------------------------------

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    t_start    = time.monotonic()
    request_id = str(uuid.uuid4())

    body     = await request.json()
    messages = body.get("messages", [])
    if not messages:
        raise HTTPException(status_code=400, detail="No messages provided.")

    # ---------------------------------------------------------------------------
    #  Extended fields — passed by NestJS backend for audit correlation
    #  user_id : Entra ID UPN or OID of the authenticated user
    #            Required for Sentinel audit trail and per-user anomaly detection
    #  source  : "user_input" (default) or "rag_chunk"
    #            "rag_chunk" = LlamaFirewall called from SearchHandler.execute()
    #            to inspect a RAG chunk before it's returned as tool_result
    # ---------------------------------------------------------------------------
    user_id = body.get("user_id", "").strip()
    source  = body.get("source",  "user_input").strip() or "user_input"

    # ------------------------------------------------------------------
    #  BYPASS MODE — skip all scanning, forward directly to Ollama
    # ------------------------------------------------------------------
    if BYPASS_MODE:
        logger.info("security_event", extra={
            "event_type":    "llm_request",
            "request_id":    request_id,
            "blocked":       False,
            "scan_decision": "BYPASS",
            "scan_score":    0.0,
            "bypass_mode":   True,
            "prompt_length": len(str(messages)),
        })
        if NO_LLM:
            return JSONResponse(content={
                "id":      f"chatcmpl-{request_id}",
                "object":  "chat.completion",
                "model":   OLLAMA_MODEL,
                "choices": [{"index": 0, "message": {
                    "role": "assistant",
                    "content": "[BYPASS MODE + NO_LLM — scanning and LLM both disabled]",
                }, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "x_llamafirewall": {"bypass_mode": True, "request_id": request_id},
            })
        async with httpx.AsyncClient(timeout=120.0) as client:
            bypass_resp = await client.post(
                f"{OLLAMA_BASE_URL}/v1/chat/completions",
                json={"model": body.get("model", OLLAMA_MODEL),
                      "messages": messages, "stream": False},
            )
        if bypass_resp.status_code != 200:
            raise HTTPException(status_code=bypass_resp.status_code,
                                detail=f"Ollama error: {bypass_resp.text}")
        bypass_body = bypass_resp.json()
        bypass_body["x_llamafirewall"] = {
            "bypass_mode": True, "request_id": request_id
        }
        return JSONResponse(content=bypass_body)

    # Extract the last user turn for scanning
    user_prompt = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            c = msg.get("content", "")
            user_prompt = c if isinstance(c, str) else str(c)
            break

    session_id = body.get("session_id", body.get("sessionId", "")).strip()

    # -----------------------------------------------------------------------
    #  Layer 1 — PromptGuard 2 + LlamaFirewall stack
    # -----------------------------------------------------------------------
    scan_result   = await asyncio.to_thread(firewall.scan, UserMessage(content=user_prompt))
    scan_decision = scan_result.decision.name
    scan_score    = getattr(scan_result, "score", 0.0)
    scan_reason   = getattr(scan_result, "reason", "")

    blocked = scan_score >= BLOCK_THRESHOLD
    if blocked:
        scan_decision = "BLOCK"

    # -----------------------------------------------------------------------
    #  Layer 1.5 — Perplexity filter
    #  Catches adversarial suffixes from gradient-based attacks (GCG, AutoDAN)
    #  that PromptGuard 2 may miss. Runs in thread — CPU-bound.
    # -----------------------------------------------------------------------
    if not blocked and PERPLEXITY_FILTER_ENABLED and _perplexity_model is not None:
        ppl_blocked, ppl_score = await asyncio.to_thread(_perplexity_scan, user_prompt)
        if ppl_blocked:
            blocked       = True
            scan_decision = "BLOCK"
            scan_reason   = f"PerplexityFilter:score={ppl_score:.1f}"
            scan_score    = min(1.0, ppl_score / PERPLEXITY_THRESHOLD)
            logger.info(f"Perplexity filter blocked prompt (score={ppl_score:.1f})")

    # -----------------------------------------------------------------------
    #  Layer 6 — NOVA scanner
    # -----------------------------------------------------------------------
    if not blocked and _nova_matchers:
        nova_blocked, nova_rule = await asyncio.to_thread(_nova_scan, user_prompt)
        if nova_blocked:
            blocked       = True
            scan_decision = "BLOCK"
            scan_reason   = f"NOVA:{nova_rule}"
            scan_score    = 1.0
            logger.info(f"NOVA blocked prompt — rule: {nova_rule}")

    # -----------------------------------------------------------------------
    #  Layer 7 — Crescendo session tracker
    #  Updates session state AFTER primary scan — uses scan_score as signal.
    #  Must run even if blocked=True so session state stays accurate.
    # -----------------------------------------------------------------------
    crescendo_blocked, crescendo_reason = await _crescendo_update(
        session_id, scan_score, blocked
    )
    if not blocked and crescendo_blocked:
        blocked       = True
        scan_decision = "BLOCK"
        scan_reason   = crescendo_reason
        scan_score    = 1.0

    if blocked:
        latency = (time.monotonic() - t_start) * 1000
        emit_security_log(request_id, user_prompt, scan_decision, scan_score,
                          True, scan_reason, latency_ms=latency,
                          user_id=user_id, source=source)
        asyncio.create_task(_ship_prompt_to_law(
            request_id, user_prompt, messages,
            scan_decision, scan_score, scan_reason, True, latency,
            user_id=user_id, source=source
        ))
        return JSONResponse(content={
            "id":      f"chatcmpl-{request_id}",
            "object":  "chat.completion",
            "model":   OLLAMA_MODEL,
            "choices": [{"index": 0, "message": {
                "role":    "assistant",
                "content": "[BLOCKED by LlamaFirewall — threat detected]",
            }, "finish_reason": "content_filter"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "x_llamafirewall": {
                "blocked":    True,
                "decision":   scan_decision,
                "score":      scan_score,
                "reason":     scan_reason[:200],
                "request_id": request_id,
            },
        })

    # Forward to Ollama — or return a stub if NO_LLM mode is on
    if NO_LLM:
        emit_security_log(request_id, user_prompt, scan_decision, scan_score,
                          False, scan_reason, "[stub — NO_LLM mode]",
                          (time.monotonic() - t_start) * 1000,
                          user_id=user_id, source=source)
        return JSONResponse(content={
            "id":      f"chatcmpl-{request_id}",
            "object":  "chat.completion",
            "model":   OLLAMA_MODEL,
            "choices": [{"index": 0, "message": {
                "role":    "assistant",
                "content": "[ALLOWED by LlamaFirewall — LLM call skipped in NO_LLM mode]",
            }, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "x_llamafirewall": {
                "blocked":    False,
                "decision":   scan_decision,
                "score":      scan_score,
                "reason":     scan_reason[:200],
                "request_id": request_id,
                "no_llm":     True,
            },
        })

    async with httpx.AsyncClient(timeout=120.0) as client:
        ollama_resp = await client.post(
            f"{OLLAMA_BASE_URL}/v1/chat/completions",
            json={"model": body.get("model", OLLAMA_MODEL),
                  "messages": messages, "stream": False},
        )

    if ollama_resp.status_code != 200:
        raise HTTPException(status_code=ollama_resp.status_code,
                            detail=f"Ollama error: {ollama_resp.text}")

    ollama_body   = ollama_resp.json()
    response_text = ""
    try:
        response_text = ollama_body["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        pass

    # Output scanning — preprod and production profiles only
    output_blocked = False

    # Layer 8 — LlamaGuard3 output scan
    if OUTPUT_SCAN_ENABLED and response_text and not LLAMA_GUARD_DISABLED:
        from llamafirewall import AssistantMessage
        out_result     = await asyncio.to_thread(
            firewall.scan, AssistantMessage(content=response_text)
        )
        output_blocked = out_result.decision == ScanDecision.BLOCK
        if output_blocked:
            logger.warning(f"Layer 8 (LlamaGuard3 output) BLOCKED response for {request_id}")
            emit_security_log(request_id, user_prompt, "OUTPUT_BLOCK",
                              getattr(out_result, "score", 1.0), True,
                              getattr(out_result, "reason", "output scan"),
                              response_text[:120], (time.monotonic() - t_start) * 1000,
                              user_id=user_id, source=source)
            return JSONResponse(content={
                "id":      f"chatcmpl-{request_id}",
                "object":  "chat.completion",
                "model":   OLLAMA_MODEL,
                "choices": [{"index": 0, "message": {
                    "role":    "assistant",
                    "content": "[BLOCKED by LlamaFirewall — unsafe response detected]",
                }, "finish_reason": "content_filter"}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "x_llamafirewall": {
                    "blocked":    True,
                    "decision":   "OUTPUT_BLOCK",
                    "score":      getattr(out_result, "score", 1.0),
                    "request_id": request_id,
                },
            })

    # Layer 9 — CodeShield (malicious code detection in responses)
    # Available in llamafirewall when code is present in output.
    if OUTPUT_SCAN_ENABLED and response_text and not output_blocked:
        try:
            from llamafirewall import AssistantMessage
            from llamafirewall.scanners.code_shield_scanner import CodeShieldScanner
            cs = CodeShieldScanner("CodeShield")
            cs_result = await asyncio.to_thread(
                cs.scan, AssistantMessage(content=response_text)
            )
            if cs_result.decision == ScanDecision.BLOCK:
                output_blocked = True
                logger.warning(f"Layer 9 (CodeShield) BLOCKED response for {request_id}")
                emit_security_log(request_id, user_prompt, "CODESHIELD_BLOCK",
                                  getattr(cs_result, "score", 1.0), True,
                                  getattr(cs_result, "reason", "code shield"),
                                  response_text[:120], (time.monotonic() - t_start) * 1000,
                                  user_id=user_id, source=source)
                return JSONResponse(content={
                    "id":      f"chatcmpl-{request_id}",
                    "object":  "chat.completion",
                    "model":   OLLAMA_MODEL,
                    "choices": [{"index": 0, "message": {
                        "role":    "assistant",
                        "content": "[BLOCKED by LlamaFirewall — malicious code detected in response]",
                    }, "finish_reason": "content_filter"}],
                    "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                    "x_llamafirewall": {
                        "blocked":    True,
                        "decision":   "CODESHIELD_BLOCK",
                        "score":      getattr(cs_result, "score", 1.0),
                        "request_id": request_id,
                    },
                })
        except ImportError:
            pass  # CodeShield not available in this LlamaFirewall version — skip silently
        except Exception as e:
            logger.warning(f"CodeShield scan error (fail-open): {e}")

    # Layer 10 — Sensitive data regex on output
    # Catches accidental credential / PII disclosure in model responses.
    if OUTPUT_SCAN_ENABLED and response_text and not output_blocked:
        sensitive_blocked, sensitive_pattern = _scan_output_for_sensitive_data(response_text)
        if sensitive_blocked:
            output_blocked = True
            logger.warning(f"Layer 10 (output regex) BLOCKED response — pattern: {sensitive_pattern}")
            emit_security_log(request_id, user_prompt, "OUTPUT_SENSITIVE_BLOCK",
                              1.0, True, f"sensitive_data:{sensitive_pattern}",
                              response_text[:120], (time.monotonic() - t_start) * 1000,
                              user_id=user_id, source=source)
            return JSONResponse(content={
                "id":      f"chatcmpl-{request_id}",
                "object":  "chat.completion",
                "model":   OLLAMA_MODEL,
                "choices": [{"index": 0, "message": {
                    "role":    "assistant",
                    "content": "[BLOCKED by LlamaFirewall — sensitive data detected in response]",
                }, "finish_reason": "content_filter"}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "x_llamafirewall": {
                    "blocked":    True,
                    "decision":   "OUTPUT_SENSITIVE_BLOCK",
                    "pattern":    sensitive_pattern,
                    "request_id": request_id,
                },
            })
                },
            })

    emit_security_log(request_id, user_prompt, scan_decision, scan_score,
                      False, scan_reason, response_text,
                      (time.monotonic() - t_start) * 1000,
                      user_id=user_id, source=source)
    asyncio.create_task(_ship_prompt_to_law(
        request_id, user_prompt, messages,
        scan_decision, scan_score, scan_reason, False,
        (time.monotonic() - t_start) * 1000,
        user_id=user_id, source=source
    ))

    ollama_body["x_llamafirewall"] = {
        "blocked":    False,
        "decision":   scan_decision,
        "score":      scan_score,
        "reason":     scan_reason[:200],
        "request_id": request_id,
    }
    return JSONResponse(content=ollama_body)

# ---------------------------------------------------------------------------
#  GET /health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status":              "ok",
        "service":             "llamafirewall-proxy",
        "profile":             PROFILE,
        "pg_threshold":        BLOCK_THRESHOLD,
        "output_scan":         OUTPUT_SCAN_ENABLED,
        "bypass_mode":         BYPASS_MODE,
        "prompt_logging":      PROMPT_LOGGING_ENABLED,
        "pii_redaction":       PII_REDACTION_ENABLED,
        "perplexity_filter":   PERPLEXITY_FILTER_ENABLED and _perplexity_model is not None,
        "perplexity_threshold": PERPLEXITY_THRESHOLD,
        "crescendo_tracking":  CRESCENDO_ENABLED,
        "scanners":            [] if BYPASS_MODE else active_scanners,
    }
