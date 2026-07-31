# SOC Triage Agent — Project Overview

A **LangGraph-powered FastAPI service** that automates SOC triage by correlating, investigating, analyzing, and producing verdicts on security alerts.

## Architecture

```
POST /triage  ──►  correlate ──► investigate ──► analyze ──► format_output ──► TriageResult
                        │                                            ▲
                        ▼ (deduplicated)                             │
                    format_output ────────────────────────────────────┘
```

**Graph nodes** (LangGraph `StateGraph`):
| Node | File | Responsibility |
|------|------|----------------|
| `correlate` | `nodes/correlate.py` | Check 1: Redis dedup. Check 2: TheHive entity match. Check 3: MITRE kill-chain story match. |
| `investigate` | `nodes/investigate.py` | ReAct agent (LLM-driven tool selection) with profile-aware prompts and tool budgets (8 new / 5 merge) |
| `analyze` | `nodes/analyze.py` | LLM-driven verdict (new alerts) or delta assessment (merge mode) |
| `format_output` | `nodes/format_output.py` | Map verdict to severity via lookup table, build `TriageResult` |

## Tools (registry in `tools/registry.py`)

| Tool | Backend | Purpose |
|------|---------|---------|
| `cortex_analyze` | Cortex (`tools/cortex.py`) | Run best analyzer on IP/domain/url/hash, extract taxonomy verdict |
| `itop_asset_lookup` | iTop CMDB (`tools/itop.py`) | Asset context: criticality, owner, services, location |
| `elasticsearch_query` | Elasticsearch (`tools/elasticsearch.py`) | Related alerts, process history, connection flows |
| `thehive_search` | TheHive (`tools/thehive.py`) | Open/closed case search, full case details |
| `sigma_rule_lookup` | Local Sigma files (`tools/sigma_rules.py`) | Rule description, FP conditions, MITRE tags |
| `qdrant_retrieve` | Qdrant vector DB (`tools/qdrant.py`) | MITRE ATT&CK, playbooks, CVE semantic search |

## Schemas (`schemas.py`)

- **`CanonicalAlert`** — normalized alert with host, user, network, process, file, observables
- **`EvidencePackage`** / **`DeltaEvidence`** — structured evidence from investigation
- **`TriageVerdict`** — analyst LLM verdict (likelihood, impact, MITRE, action)
- **`CorrelationResult`** — dedup/merge/new routing decision
- **`TriageResult`** — final API response

## Prompts (`prompts/`)

- **`investigator.py`** — SOC investigator system prompt with 5 investigation profiles (`network_threat`, `endpoint_behavior`, `malicious_file`, `network_anomaly`, `log_anomaly`) + generic fallback
- **`analyst.py`** — SOC analyst prompt with strict JSON output, 7-step reasoning process, separate merge-mode prompt, plus a GBNF grammar for constrained LLM generation

## Configuration (`config.py`)

Mandatory env vars: `CORTEX_URL/API_KEY`, `THEHIVE_URL/API_KEY`, `ITOP_URL/USER/KEY`, `ES_URL`, `LLM_BASE_URL/MODEL`. Optional: `QDRANT_URL`, `REDIS_URL`, `SIGMA_RULES_PATH`, tunables (`MAX_TOOL_CALLS`, `DEDUP_WINDOW_SECONDS`).

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/triage` | Submit `CanonicalAlert`, returns `TriageResult` |

## Data Flow

1. **Correlate** — Check 1: Redis SHA-256 dedup fingerprint → short-circuit if duplicate. Check 2: TheHive entity search by observable/host/user → merge. Check 3: MITRE kill-chain progression on same host via 61-technique tactic mapping → merge.
2. **Investigate** — LangGraph `create_react_agent` with LLM-driven tool selection, profile-aware system prompt, and strict tool call budget (8 new / 5 merge). Produces `EvidencePackage` or `DeltaEvidence`.
3. **Analyze** — LLM (`ChatOpenAI` → Ollama) receives evidence summary → structured verdict or delta assessment. Fallback to `needs_review` if JSON parsing fails.
4. **Format output** — Map `(likelihood, impact)` to severity via 16-cell lookup table. Package everything into `TriageResult`.

## Qdrant Ingestion (`scripts/ingest_qdrant.py`)

Three subcommands to populate vector collections using `BAAI/bge-large-en-v1.5` (1024-dim):

| Command | Source | Payload | Volume |
|---------|--------|---------|--------|
| `mitre` | MITRE CTI GitHub (STIX) | technique_id, technique, tactic, sub_technique, description | ~850 techniques |
| `cve` | NVD API 2.0 (paginated) | cve_id, description, cvss_score, affected_software | up to 5,000 |
| `playbooks <dir>` | Local .md/.yaml with front matter | title, content, tags, source | all files in dir |

```bash
python scripts/ingest_qdrant.py all --playbooks-dir=./playbooks
```

## Tests

```bash
python -m pytest tests/ -v
```

61 tests across 7 test files:
| File | Coverage |
|------|----------|
| `test_schemas.py` | All 11 Pydantic models: construction, defaults, serialization |
| `test_format_output.py` | Severity table (all 16 cells), dedup/merge/new code paths, fallbacks, trace passthrough |
| `test_correlate.py` | Dedup, entity match, story match with 4 tactic ordering tests, all 3 correlation routes |
| `test_analyze.py` | JSON extraction (7 edge cases), evidence summarization, fallback on None |
| `test_graph.py` | Conditional routing (dedup→format, merge/new→investigate), node presence |
| `test_prompts.py` | Investigator prompt building (all profiles), analyst prompt + schema, GBNF |

## Running

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in credentials
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Dependencies

`fastapi`, `uvicorn`, `langgraph`, `langchain`, `langchain-community`, `langchain-openai`, `pydantic`, `requests`, `python-dotenv`, `qdrant-client`, `fastembed`, `redis`, `pyyaml`
