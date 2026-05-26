# =============================================================================
#  LlamaFirewall Proxy — CPU Build
#  For: corp-lab VM, corp-preprod AKS (CPU node pool)
#
#  Usage:
#    docker build -t llamafirewall-proxy:cpu -f Dockerfile .
#    docker run -p 8080:8080 \
#      -e OLLAMA_BASE_URL=http://<ollama-host>:11434 \
#      -e HUGGING_FACE_HUB_TOKEN=<your-hf-token> \
#      llamafirewall-proxy:cpu
#
#  For GPU (corp-prod AKS with T4/A100 node pool):
#    Use Dockerfile.gpu instead.
#
#  Environment variables:
#    OLLAMA_BASE_URL          — Ollama endpoint (default: http://localhost:11434)
#    HUGGING_FACE_HUB_TOKEN   — HuggingFace token for PromptGuard 2
#    LLAMAFIREWALL_PROFILE    — lab | preprod | production (default: lab)
#    PROMPTGUARD_THRESHOLD    — 0.05 | 0.10 | 0.15 (default: 0.05)
#    OUTPUT_SCAN_ENABLED      — 0 | 1 (default: 0)
#    NOVA_LLM_ENABLED         — 0 | 1 (default: 0)
#    LLAMA_GUARD_DISABLED     — 0 | 1 (default: 0)
#    BYPASS_MODE              — 0 | 1 (default: 0)
#    NO_LLM                   — 0 | 1 (default: 0)
# =============================================================================

# Python 3.10 — required by LlamaFirewall (tested against 3.10.x)
FROM python:3.10-slim

# ---------------------------------------------------------------------------
#  System dependencies
# ---------------------------------------------------------------------------
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        git \
        curl \
        build-essential \
        libssl-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
#  Python dependencies
#  torch CPU-only build — much smaller than the default CUDA build (~700 MB vs 3 GB)
# ---------------------------------------------------------------------------
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        torch \
        --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir \
        llamafirewall \
        transformers \
        fastapi \
        uvicorn \
        httpx \
        nova-hunting

# ---------------------------------------------------------------------------
#  HfFolder compatibility patch
#  huggingface_hub >= 0.25 removed HfFolder — LlamaFirewall still imports it.
# ---------------------------------------------------------------------------
RUN python3 -c "\
import os, sys; \
path = next((os.path.join(r, 'llamafirewall/scanners/promptguard_utils.py') \
    for r in sys.path if os.path.exists(os.path.join(r, 'llamafirewall/scanners/promptguard_utils.py'))), None); \
content = open(path).read(); \
old = 'from huggingface_hub import HfFolder, login'; \
new = '''from huggingface_hub import login\ntry:\n    from huggingface_hub import HfFolder\nexcept ImportError:\n    import huggingface_hub as _hf\n    class HfFolder:\n        @staticmethod\n        def get_token(): return _hf.get_token()\n        @staticmethod\n        def save_token(token): pass'''; \
open(path, 'w').write(content.replace(old, new)) if old in content else None; \
print('HfFolder patch applied' if old in content else 'HfFolder already patched')"

# ---------------------------------------------------------------------------
#  Application files
# ---------------------------------------------------------------------------
WORKDIR /app

COPY proxy.py                                     ./proxy.py
COPY social_engineering_pt.nov                    ./nova-rules-custom/social_engineering_pt.nov

# Clone NOVA official rules
RUN git clone --depth 1 https://github.com/Nova-Hunting/nova-rules ./nova-rules

# ---------------------------------------------------------------------------
#  Pre-download PromptGuard 2 weights at build time
#  This bakes the model into the image so containers start immediately
#  without needing to download ~170 MB on first request.
#
#  Requires HUGGING_FACE_HUB_TOKEN as a build arg.
#  Build: docker build --build-arg HF_TOKEN=hf_xxx -t llamafirewall-proxy:cpu .
#
#  If token is not provided at build time, the model downloads on first request.
# ---------------------------------------------------------------------------
ARG HF_TOKEN=""
ENV HF_HOME=/app/.cache/huggingface
RUN if [ -n "${HF_TOKEN}" ]; then \
        python3 -c "\
import os; \
os.environ['HUGGING_FACE_HUB_TOKEN'] = '${HF_TOKEN}'; \
from transformers import AutoTokenizer, AutoModelForSequenceClassification; \
model_id = 'meta-llama/Llama-Prompt-Guard-2-86M'; \
AutoTokenizer.from_pretrained(model_id, token='${HF_TOKEN}'); \
AutoModelForSequenceClassification.from_pretrained(model_id, token='${HF_TOKEN}'); \
print('PromptGuard 2 weights cached.')"; \
    else \
        echo "No HF_TOKEN provided — PromptGuard 2 will download on first request."; \
    fi

# ---------------------------------------------------------------------------
#  Runtime environment defaults
#  All overridable via docker run -e or Kubernetes ConfigMap/Secret
# ---------------------------------------------------------------------------
ENV LLAMAFIREWALL_PROFILE=lab \
    PROMPTGUARD_THRESHOLD=0.05 \
    OUTPUT_SCAN_ENABLED=0 \
    NOVA_LLM_ENABLED=0 \
    LLAMA_GUARD_DISABLED=0 \
    BYPASS_MODE=0 \
    NO_LLM=0 \
    OLLAMA_BASE_URL=http://localhost:11434 \
    PYTHONUNBUFFERED=1

# ---------------------------------------------------------------------------
#  Non-root user — security best practice for AKS
# ---------------------------------------------------------------------------
RUN useradd -m -u 1000 llamafirewall
RUN chown -R llamafirewall:llamafirewall /app
USER llamafirewall

# ---------------------------------------------------------------------------
#  Health check
# ---------------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

EXPOSE 8080

# ---------------------------------------------------------------------------
#  Entrypoint
# ---------------------------------------------------------------------------
CMD ["uvicorn", "proxy:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--workers", "1", \
     "--log-level", "warning"]
