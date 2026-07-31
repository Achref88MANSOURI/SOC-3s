# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A LangGraph-powered FastAPI service (`agent-service`) that automates SOC (Security Operations Center) alert triage. It sits between n8n (deterministic ingestion layer, not in this repo) and the security stack (TheHive, Cortex, iTop, Elasticsearch, Qdrant, local Sigma rules). n8n POSTs a normalized `canonical_alert` to `/triage`; this service correlates it against existing cases, investigates it with an LLM tool-calling agent, produces a verdict with a second LLM call, and returns a `triage_result` that n8n acts on (create case / close as FP / merge / escalate / dedupe).

`CONTEXT.md` is the original architecture/design reference (pipeline diagram, severity table, per-agent mission specs, build-order phases). Treat it as the source of design intent — consult it for *why* a node behaves a certain way. `preview.md` is a shorter, more current as-built summary of the same system. Where either disagrees with the actual code, the code wins.

## Commands

```bash
# Local static checks — no network calls, no API keys required. Run this first.
./test.sh

# Run the full test suite directly
python -m pytest tests/ -v

# Run a single test file / test
python -m pytest tests/test_correlate.py -v
python -m pytest tests/test_correlate.py::test_kill_chain_progression_true -v

# Start the service (requires a filled-in .env — see Configuration below)
uvicorn main:app --host 0.0.0.0 --port 8000

# Inspect resolved config / verify required env vars are set (masks secrets)
python config.py

# Populate Qdrant collections (MITRE ATT&CK, CVE, playbooks)
python scripts/ingest_qdrant.py all --playbooks-dir=./playbooks
python scripts/ingest_qdrant.py mitre
python scripts/ingest_qdrant.py cve
```

Note: `test.sh` invokes `pip install -r requirements.txt -r requirements-dev.txt`, but `requirements-dev.txt` does not currently exist in the repo — create it (pytest, etc.) or adjust the script before relying on `test.sh`'s dependency-install step.

There is no separate lint/format command configured — match existing style (`from __future__ import annotations` at the top of every module, type hints throughout).

## Architecture

### Request flow

```
POST /triage (main.py)
   │
   ▼
graph.py — LangGraph StateGraph, sequential with one conditional branch:

  correlate ──(deduplicated)──► format_output ──► return TriageResult
     │
     └─(new | merge)──► investigate ──► analyze ──► format_output ──► return TriageResult
```

State is a single `TriageState` TypedDict (schemas.py) threaded through every node — each node reads what it needs and writes its output field(s) back into state.

### The four nodes (`nodes/`)

1. **`correlate.py`** — pure Python, no LLM. Three checks, first hit wins:
   - **Dedup**: SHA-256 fingerprint of `rule.uuid + host + user (+ first 3 external IPs)` in Redis, `DEDUP_WINDOW_SECONDS` window. Redis is optional — if `REDIS_URL` is unset, dedup silently no-ops (never blocks the pipeline).
   - **Entity match**: query TheHive for open cases sharing an observable/host/user → `mode=merge`.
   - **Story match**: MITRE kill-chain progression — extracts ATT&CK technique IDs from the alert's Sigma rule tags and from candidate cases' tags, maps techniques → tactics via a hardcoded `TECHNIQUE_TO_TACTIC` table, and checks if the alert's tactic is *later* in `TACTIC_ORDER` than anything already in the case → `mode=merge`.
   - No match → `mode=new`.
   Sets `state["mode"]` and, for merge, `state["existing_case_context"]`.

2. **`investigate.py`** — Agent 1 ("Investigator"), a `langgraph.prebuilt.create_react_agent` with all tools from `tools/registry.py`. System prompt is built by `prompts/investigator.py` based on `investigation_profile` (from the alert) and `mode`. Tool-call budget: `MAX_TOOL_CALLS_NEW` (default 8) for new alerts, `MAX_TOOL_CALLS_MERGE` (default 5) for merges — enforced via the ReAct agent's `recursion_limit`, not a hard tool-call counter. Expects the agent's final message to be JSON matching `EvidencePackage` (new) or `DeltaEvidence` (merge). If the model doesn't return parseable JSON, falls back to reconstructing evidence directly from the raw tool-call results (`_build_from_tool_results`) rather than failing the request.

3. **`analyze.py`** — Agent 2 ("Analyst"), a single non-tool-calling LLM call. Never sees raw evidence — only a truncated/summarized view of `EvidencePackage`/`DeltaEvidence` (this summarization is a deliberate prompt-injection firewall: attacker-controlled strings from logs/observables should already have been distilled into typed fields by Agent 1). System prompt from `prompts/analyst.py`. On unparseable JSON output, falls back to a safe `needs_review` / `merge_quiet` verdict rather than raising.

4. **`format_output.py`** — pure Python. Applies the `(likelihood, impact_if_true) → severity` lookup table (`SEVERITY_TABLE`, mirrors the table in `CONTEXT.md` §2) to compute severity — this is *never* an LLM output directly. Builds the final `TriageResult` returned to n8n. Handles three shapes: deduplicated (short-circuit), merge (delta verdict), new (full verdict).

### Tools (`tools/`)

Each backend has its own module (`cortex.py`, `itop.py`, `elasticsearch.py`, `thehive.py`, `sigma_rules.py`, `qdrant.py`) with plain Python functions; `tools/registry.py` wraps the ones exposed to Agent 1 with `@langchain_core.tools.tool` and collects them into `TOOLS`. All tools are read-only. `sigma_rules.py` reads rule definitions from the local filesystem (`SIGMA_RULES_PATH`, default `/opt/so/rules/sigma`), not an API. When adding a new tool, add the backend function to its own `tools/*.py` module, then wrap and register it in `tools/registry.py` — the investigator prompt (`prompts/investigator.py`) may also need updating if the tool should be steered by `investigation_profile`.

### Prompts (`prompts/`)

- `investigator.py` — `build_prompt(profile, mode)` composes a base mission prompt with a profile-specific block (`network_threat`, `endpoint_behavior`, `malicious_file`, `network_anomaly`, `log_anomaly`, plus a generic fallback) that hints which tools to prefer/avoid. Profiles guide but don't hard-restrict tool choice.
- `analyst.py` — `build_prompt(mode)` / `output_schema(mode)` define the analyst's reasoning structure and expected JSON output shape (also referenced for a GBNF grammar in the original design — see `CONTEXT.md` §4 for the full 7-step reasoning spec).

### Schemas (`schemas.py`)

Single file, not a package (despite `CONTEXT.md`'s original `schemas/models.py` plan). All Pydantic models plus the LangGraph `TriageState` TypedDict live here: `CanonicalAlert` (+ `Rule`/`Host`/`User`/`Network`/`Process`/`File`/`Observables`), `EvidencePackage`/`DeltaEvidence`, `TriageVerdict`/`DeltaVerdict`, `CorrelationResult`, `TriageResult`.

### Configuration (`config.py`)

Loads `.env` via `python-dotenv` at import time and **raises `RuntimeError` immediately if any required var is missing** — `CORTEX_URL/API_KEY`, `THEHIVE_URL/API_KEY`, `ITOP_URL/USER/KEY`, `ES_URL`, `LLM_BASE_URL/MODEL`. Everything else is optional with defaults (`QDRANT_URL`, `REDIS_URL`, `SIGMA_RULES_PATH`, `MAX_TOOL_CALLS_NEW/MERGE`, `DEDUP_WINDOW_SECONDS`). Because of the fail-fast check, *any* module that imports `config` (directly or transitively) will blow up without a valid `.env` — this includes running individual test files if they import through `schemas`/`nodes`. Run `python config.py` to print resolved settings with secrets masked.

## Key design invariants (don't break these)

- **Severity is always computed, never model-generated.** The LLM produces `likelihood` + `impact_if_true`; `format_output.py`'s `SEVERITY_TABLE` is the only place severity is decided.
- **Agent 2 (analyze) never receives raw logs, raw API responses, or unsummarized attacker-controlled strings** — only Agent 1's structured, typed evidence summary. This boundary is the prompt-injection defense; don't pipe raw tool output directly into the analyst prompt.
- **Every LLM-facing node has a non-LLM fallback path** (`investigate.py`'s `_build_from_tool_results`, `analyze.py`'s parse-failure defaults to `needs_review`/`merge_quiet`). Preserve this — the service must degrade to a safe, flagged-for-review state rather than 500 or hallucinate a verdict when the model misbehaves.
- **All tools in `tools/registry.py` are read-only.** This service investigates and recommends; it does not mutate TheHive/iTop/Elasticsearch/Cortex state itself — n8n performs the actual case actions based on `TriageResult.action`.
