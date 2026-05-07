"""
LlamaFirewall Proxy — OpenAI-compatible endpoint on :8080

Sits between PyRIT (caller) and Ollama (LLM backend).
Accepts /v1/chat/completions requests, scans with PromptGuard 2,
forwards clean prompts to Ollama, and returns structured responses
with x_llamafirewall metadata attached.

Deployed to: /opt/llamafirewall/proxy.py
Managed by:  llamafirewall.service (systemd)
"""

import asyncio
import json
import logging
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
#  LlamaFirewall — PoC config
#  scanners must be a dict keyed by Role (not a list).
#  USER input is scanned by PromptGuard 2 (86M params, CPU-friendly).
#  Output scanning is disabled for PoC to save RAM on the B4ms.
# ---------------------------------------------------------------------------

logger.info("Initialising LlamaFirewall...")

firewall = LlamaFirewall({
    Role.USER:      [ScannerType.PROMPT_GUARD],
    Role.ASSISTANT: [],
    Role.SYSTEM:    [],
    Role.TOOL:      [],
    Role.MEMORY:    [],
})

logger.info("LlamaFirewall ready.")

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL    = "phi3:mini"

app = FastAPI(title="LlamaFirewall Proxy", version="0.1.0")

# ---------------------------------------------------------------------------
#  Security event logger
# ---------------------------------------------------------------------------

def emit_security_log(request_id, prompt, scan_decision, scan_score,
                      blocked, response_text="", latency_ms=0.0):
    logger.info("security_event", extra={
        "event_type":      "llm_request",
        "request_id":      request_id,
        "blocked":         blocked,
        "scan_decision":   scan_decision,
        "scan_score":      round(scan_score, 4),
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

    # Run the blocking scan in a thread — keeps the async event loop free
    scan_result   = await asyncio.to_thread(firewall.scan, UserMessage(content=user_prompt))
    scan_decision = scan_result.decision.name
    scan_score    = getattr(scan_result, "score", 0.0)
    blocked       = scan_result.decision == ScanDecision.BLOCK

    if blocked:
        emit_security_log(request_id, user_prompt, scan_decision, scan_score,
                          True, latency_ms=(time.monotonic() - t_start) * 1000)
        return JSONResponse(content={
            "id":      f"chatcmpl-{request_id}",
            "object":  "chat.completion",
            "model":   OLLAMA_MODEL,
            "choices": [{"index": 0, "message": {
                "role":    "assistant",
                "content": "[BLOCKED by LlamaFirewall — prompt injection / jailbreak detected]",
            }, "finish_reason": "content_filter"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "x_llamafirewall": {
                "blocked":    True,
                "decision":   scan_decision,
                "score":      scan_score,
                "request_id": request_id,
            },
        })

    # Forward to Ollama
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
                      False, response_text, (time.monotonic() - t_start) * 1000)

    ollama_body["x_llamafirewall"] = {
        "blocked":    False,
        "decision":   scan_decision,
        "score":      scan_score,
        "request_id": request_id,
    }
    return JSONResponse(content=ollama_body)

# ---------------------------------------------------------------------------
#  GET /health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "service": "llamafirewall-proxy"}
