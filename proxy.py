"""
LlamaFirewall Proxy — OpenAI-compatible endpoint on :8080

Sits between PyRIT (caller) and Ollama (LLM backend).
Accepts /v1/chat/completions requests, scans with a layered scanner stack,
forwards clean prompts to Ollama, and returns structured responses
with x_llamafirewall metadata attached.

Scanner stack (input):
  1. PromptGuard 2   — prompt injection / jailbreak detection (threshold 0.05)
  2. HiddenASCII     — BiDi text, invisible characters, encoding tricks
  3. Regex (default) — built-in prompt injection, PII patterns
  4. custom_patterns — XSS, SQL injection, credential extraction, tool abuse

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
    ],
    Role.ASSISTANT: [],
    Role.SYSTEM:    [],
    Role.TOOL:      [],
    Role.MEMORY:    [],
})

logger.info("LlamaFirewall ready — 4 scanners active.")

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL    = "phi3:mini"

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

app = FastAPI(title="LlamaFirewall Proxy", version="0.1.0")

# ---------------------------------------------------------------------------
#  Security event logger
# ---------------------------------------------------------------------------

def emit_security_log(request_id, prompt, scan_decision, scan_score,
                      blocked, scan_reason="", response_text="", latency_ms=0.0):
    logger.info("security_event", extra={
        "event_type":      "llm_request",
        "request_id":      request_id,
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

    # Extract the last user turn for scanning
    user_prompt = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            c = msg.get("content", "")
            user_prompt = c if isinstance(c, str) else str(c)
            break

    # Run the full scanner stack in a thread — keeps the async event loop free
    scan_result   = await asyncio.to_thread(firewall.scan, UserMessage(content=user_prompt))
    scan_decision = scan_result.decision.name
    scan_score    = getattr(scan_result, "score", 0.0)
    scan_reason   = getattr(scan_result, "reason", "")

    # ---------------------------------------------------------------------------
    #  Custom threshold — applies to PromptGuard 2 scores.
    #  REGEX / HIDDEN_ASCII / custom_patterns block at score 1.0 (always passes).
    #  This threshold catches marginal PromptGuard scores (0.05-0.49) that the
    #  internal decision would have allowed.
    #  Baseline prompts score <0.003 — no false positive risk at 0.05.
    # ---------------------------------------------------------------------------
    BLOCK_THRESHOLD = 0.05
    blocked = scan_score >= BLOCK_THRESHOLD
    if blocked:
        scan_decision = "BLOCK"

    if blocked:
        emit_security_log(request_id, user_prompt, scan_decision, scan_score,
                          True, scan_reason,
                          latency_ms=(time.monotonic() - t_start) * 1000)
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
                          (time.monotonic() - t_start) * 1000)
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

    emit_security_log(request_id, user_prompt, scan_decision, scan_score,
                      False, scan_reason, response_text,
                      (time.monotonic() - t_start) * 1000)

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
        "status":   "ok",
        "service":  "llamafirewall-proxy",
        "scanners": ["PromptGuard2", "HiddenASCII", "Regex", "CustomPatterns"],
    }
