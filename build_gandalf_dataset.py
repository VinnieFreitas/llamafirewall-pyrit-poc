"""
=============================================================================
 build_gandalf_dataset.py
 Downloads and curates prompts from three Lakera Gandalf datasets into
 gandalf_attacks.yaml — a separate adversarial dataset for LlamaFirewall
 red-teaming, complementing custom_attacks.yaml.

 Sources:
   - Lakera/gandalf_ignore_instructions  (classic "ignore previous" injections)
   - Lakera/gandalf_summarization        (indirect injection via document summary)
   - Lakera/mosscap_prompt_injection     (DEF CON 2023 variant — more adversarial)

 Output: gandalf_attacks.yaml (~60 curated prompts, all expect_blocked: true)

 Usage:
   source venv/bin/activate
   pip install datasets pyyaml
   python3 build_gandalf_dataset.py

   # Run PyRIT against LlamaFirewall with the new dataset
   python3 pyrit_redteam.py \
     --prompts-file gandalf_attacks.yaml \
     --endpoint http://localhost:8080/v1
=============================================================================
"""

import hashlib
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: pip install pyyaml")
    sys.exit(1)

try:
    from datasets import load_dataset
except ImportError:
    print("ERROR: pip install datasets")
    sys.exit(1)

# ---------------------------------------------------------------------------
#  Config
# ---------------------------------------------------------------------------

# How many prompts to keep per source dataset
KEEP_PER_SOURCE = {
    "gandalf_ignore_instructions": 25,
    "gandalf_summarization":       20,
    "mosscap_prompt_injection":    15,
}

# Minimum/maximum prompt length — filter out trivially short or huge prompts
MIN_CHARS = 20
MAX_CHARS = 800

# Minimum similarity threshold for gandalf_ignore_instructions
MIN_SIMILARITY = 0.85

# ---------------------------------------------------------------------------
#  Deduplication helper
# ---------------------------------------------------------------------------

def _fingerprint(text: str) -> str:
    """Short fingerprint — catches near-duplicates that differ only in case/spaces."""
    normalised = re.sub(r'\s+', ' ', text.lower().strip())
    return hashlib.md5(normalised[:80].encode()).hexdigest()

# ---------------------------------------------------------------------------
#  Source 1: gandalf_ignore_instructions
#  Columns: text (str), similarity (float)
#  Filter:  similarity >= MIN_SIMILARITY, diverse coverage
# ---------------------------------------------------------------------------

def load_gandalf_ignore(n: int) -> list[dict]:
    print(f"\n==> Loading gandalf_ignore_instructions...")
    ds = load_dataset(
        "Lakera/gandalf_ignore_instructions",
        name="default",
        split="train",
        trust_remote_code=True,
    )
    print(f"    Total rows: {len(ds)}")

    # Sort by similarity descending — keep highest-confidence injections
    rows = sorted(
        [r for r in ds if r["similarity"] >= MIN_SIMILARITY],
        key=lambda r: r["similarity"],
        reverse=True,
    )

    seen, selected = set(), []
    for row in rows:
        text = row["text"].strip()
        if len(text) < MIN_CHARS or len(text) > MAX_CHARS:
            continue
        fp = _fingerprint(text)
        if fp in seen:
            continue
        seen.add(fp)
        selected.append({
            "name":           f"gandalf_ignore_{len(selected)+1:03d}",
            "category":       "prompt_injection",
            "expect_blocked": True,
            "notes":          f"Lakera/gandalf_ignore_instructions — similarity={row['similarity']:.3f}",
            "prompt":         text,
        })
        if len(selected) >= n:
            break

    print(f"    Selected: {len(selected)} prompts")
    return selected

# ---------------------------------------------------------------------------
#  Source 2: gandalf_summarization
#  Columns: text (str), label (str — 'injection' or 'benign')
#  We keep only label == 'injection'
# ---------------------------------------------------------------------------

def load_gandalf_summarization(n: int) -> list[dict]:
    print(f"\n==> Loading gandalf_summarization...")
    try:
        ds = load_dataset(
            "Lakera/gandalf_summarization",
            split="train",
            trust_remote_code=True,
        )
    except Exception as e:
        print(f"    WARNING: Could not load dataset — {e}")
        return []

    print(f"    Total rows: {len(ds)}")
    print(f"    Columns: {ds.column_names}")

    # Try to find injection rows — column name varies by dataset version
    text_col   = next((c for c in ds.column_names if "text" in c.lower() or "prompt" in c.lower()), ds.column_names[0])
    label_col  = next((c for c in ds.column_names if "label" in c.lower() or "inject" in c.lower()), None)

    rows = list(ds)
    if label_col:
        rows = [r for r in rows if str(r[label_col]).lower() in ("injection", "true", "1", "injected")]

    seen, selected = set(), []
    for row in rows:
        text = str(row[text_col]).strip()
        if len(text) < MIN_CHARS or len(text) > MAX_CHARS:
            continue
        fp = _fingerprint(text)
        if fp in seen:
            continue
        seen.add(fp)
        selected.append({
            "name":           f"gandalf_summarization_{len(selected)+1:03d}",
            "category":       "indirect_injection",
            "expect_blocked": True,
            "notes":          "Lakera/gandalf_summarization — indirect injection via document summary",
            "prompt":         text,
        })
        if len(selected) >= n:
            break

    print(f"    Selected: {len(selected)} prompts")
    return selected

# ---------------------------------------------------------------------------
#  Source 3: mosscap_prompt_injection (DEF CON 2023)
#  Columns: level (str), prompt (str), answer (str)
#  Higher levels = stronger defenses = harder attacks
# ---------------------------------------------------------------------------

def load_mosscap(n: int) -> list[dict]:
    print(f"\n==> Loading mosscap_prompt_injection...")
    try:
        ds = load_dataset(
            "Lakera/mosscap_prompt_injection",
            split="train",
            trust_remote_code=True,
        )
    except Exception as e:
        print(f"    WARNING: Could not load dataset — {e}")
        return []

    print(f"    Total rows: {len(ds)}")
    print(f"    Columns: {ds.column_names}")

    # Prefer harder levels (5-8) — more sophisticated attacks
    rows = sorted(
        list(ds),
        key=lambda r: -int(str(r.get("level", "Level 1")).replace("Level ", "") or 1)
    )

    text_col = next((c for c in ds.column_names if "prompt" in c.lower() or "text" in c.lower()), ds.column_names[0])

    seen, selected = set(), []
    for row in rows:
        text = str(row[text_col]).strip()
        if len(text) < MIN_CHARS or len(text) > MAX_CHARS:
            continue
        # Skip rows that look like benign questions (no injection signal)
        injection_signals = [
            "ignore", "disregard", "forget", "override", "bypass",
            "password", "secret", "instruction", "previous", "system"
        ]
        if not any(sig in text.lower() for sig in injection_signals):
            continue
        fp = _fingerprint(text)
        if fp in seen:
            continue
        seen.add(fp)
        level = str(row.get("level", "unknown"))
        selected.append({
            "name":           f"mosscap_{len(selected)+1:03d}",
            "category":       "evasion",
            "expect_blocked": True,
            "notes":          f"Lakera/mosscap_prompt_injection — {level} (DEF CON 2023)",
            "prompt":         text,
        })
        if len(selected) >= n:
            break

    print(f"    Selected: {len(selected)} prompts")
    return selected

# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  Gandalf Dataset Builder")
    print("  Building gandalf_attacks.yaml from 3 Lakera datasets")
    print("=" * 60)

    all_prompts = []
    all_prompts += load_gandalf_ignore(KEEP_PER_SOURCE["gandalf_ignore_instructions"])
    all_prompts += load_gandalf_summarization(KEEP_PER_SOURCE["gandalf_summarization"])
    all_prompts += load_mosscap(KEEP_PER_SOURCE["mosscap_prompt_injection"])

    # Final dedup across all sources
    seen, deduped = set(), []
    for p in all_prompts:
        fp = _fingerprint(p["prompt"])
        if fp not in seen:
            seen.add(fp)
            deduped.append(p)

    print(f"\n==> Total prompts after dedup: {len(deduped)}")

    # Category summary
    from collections import Counter
    cats = Counter(p["category"] for p in deduped)
    for cat, count in cats.items():
        print(f"    {cat:30s}: {count}")

    # Write YAML
    out_path = Path("gandalf_attacks.yaml")
    output = {
        "description": (
            "Adversarial prompts curated from three Lakera Gandalf datasets: "
            "gandalf_ignore_instructions, gandalf_summarization, mosscap_prompt_injection. "
            "All prompts are real human-generated attacks from the Gandalf red-teaming game. "
            "Separate from custom_attacks.yaml — run independently for cross-dataset validation."
        ),
        "sources": [
            "https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions",
            "https://huggingface.co/datasets/Lakera/gandalf_summarization",
            "https://huggingface.co/datasets/Lakera/mosscap_prompt_injection",
        ],
        "total": len(deduped),
        "prompts": deduped,
    }

    out_path.write_text(
        yaml.dump(output, allow_unicode=True, default_flow_style=False,
                  sort_keys=False, width=120),
        encoding="utf-8",
    )

    print(f"\n✓  Saved: {out_path} ({out_path.stat().st_size // 1024} KB)")
    print(f"\n  Run PyRIT against LlamaFirewall:")
    print(f"  python3 pyrit_redteam.py --prompts-file gandalf_attacks.yaml")
