# Two-Model LLM Strategy

## Overview

The agent pipeline now supports **two separate LLM configurations** to optimize latency and reasoning quality:

- **Perceive & Investigate agents** (Agent 1): Use a fast, smaller model for rapid tool-calling
- **Analyze agent** (Agent 2): Use a larger, higher-quality model for final verdict reasoning

## Configuration

### Minimal Setup (Use Same Model Everywhere)

Just set the shared model:

```bash
LLM_BASE_URL=http://172.20.24.225:11434/v1
LLM_MODEL=qwen3.5:4b
# LLM_ANALYZE_* will fall back to these
```

### Two-Model Setup (Recommended)

```bash
# Fast model for tool-calling agents (perceive, investigate)
LLM_BASE_URL=http://172.20.24.225:11434/v1
LLM_MODEL=qwen3.5:4b

# Larger model for final reasoning (analyze)
LLM_ANALYZE_BASE_URL=http://172.20.24.225:11434/v1
LLM_ANALYZE_MODEL=qwen3:8b
```

### Different Endpoints

Use different LLM services if desired (e.g., fast local + powerful remote):

```bash
# Perceive/investigate: local CPU inference
LLM_BASE_URL=http://localhost:11434/v1
LLM_MODEL=qwen3.5:4b

# Analyze: higher-quality remote model
LLM_ANALYZE_BASE_URL=https://api.openai.com/v1
LLM_ANALYZE_MODEL=gpt-4o-mini
LLM_ANALYZE_API_KEY=sk-...
```

## Implementation Details

### Config Loading

The `config.py` module provides:
- `LLM_MODEL` / `LLM_BASE_URL` / `LLM_API_KEY` — shared (perceive, investigate)
- `LLM_ANALYZE_MODEL` / `LLM_ANALYZE_BASE_URL` / `LLM_ANALYZE_API_KEY` — analyze only

Each `LLM_ANALYZE_*` falls back to its `LLM_*` counterpart if not set.

### Agent-Specific Behavior

| Agent | Uses | Rationale |
|-------|------|-----------|
| `nodes/perceive.py` | `LLM_MODEL` / `LLM_BASE_URL` | Makes many tool calls; needs speed |
| `nodes/investigate.py` | `LLM_MODEL` / `LLM_BASE_URL` | Makes many tool calls; needs speed |
| `nodes/analyze.py` | `LLM_ANALYZE_MODEL` / `LLM_ANALYZE_BASE_URL` | Single call; needs high-quality reasoning |

### Quality vs. Latency Tradeoff

Current setup (`qwen3.5:4b` + `qwen3:8b`):
- **Perceive/Investigate** (fast): 15–25s per call
- **Analyze** (quality): 35–50s per call
- **Total per alert**: ~17 minutes on CPU-only hardware (includes embedding download on first run)

If you have GPU:
- Latency cuts to 2–5 minutes per alert
- Speed gain applies to both models

## Monitoring

Check which models are loaded:

```bash
python3 config.py
```

Output shows both LLM configurations separately:

```
LLM (shared — perceive, investigate)
  LLM_BASE_URL         = http://172.20.24.225:11434/v1
  LLM_MODEL            = qwen3.5:4b
  LLM_API_KEY          = (not set)

LLM (analyze — set separately to use a different model)
  LLM_ANALYZE_BASE_URL = http://172.20.24.225:11434/v1
  LLM_ANALYZE_MODEL    = qwen3:8b
  LLM_ANALYZE_API_KEY  = (not set)
```

## Testing

All existing tests pass unchanged — the split is transparent to the test suite:

```bash
python3 -m pytest tests/ -v
```

The two-model strategy is a deployment detail that doesn't affect alert-triage logic.
