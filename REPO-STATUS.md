# REPO-STATUS.md — SOC-3s agent-service, current state

**Compiled:** 2026-08-05, from a full read of every source file in this repo
(all of `nodes/`, `tools/`, `prompts/`, `tests/`, `scripts/`, plus
`main.py`, `graph.py`, `schemas.py`, `alert_builder.py`, `config.py`,
`CLAUDE.md`, `CHANGES.md`, `SOC-3s-ARCHITECTURE-v3-final.md`,
`N8N-INTEGRATION.md`, `test.sh`, `requirements.txt`, `.gitignore`). No `.env`
file exists inside this worktree — `config.py` (via `python-dotenv`) walks up
the directory tree and picks up `/home/ai-vm/agent-service/.env`, the main
checkout's file, shared across worktrees.

This document describes what the **code** does. Where the code disagrees with
`CHANGES.md` or `SOC-3s-ARCHITECTURE-v3-final.md`, that is called out
explicitly under §9. Nothing here is inferred from doc claims alone unless
stated as such.

---

## 1. Project overview

SOC-3s `agent-service` is a LangGraph/FastAPI service that automates the
triage step of SOC (Security Operations Center) alert handling. It sits
between two systems it does not own:

```
Security Onion (Suricata / Sigma-ElastAlert2 / YARA-Strelka detections)
        │  webhook — only trigger source is .ds-logs-detections.alerts-so-*
        ▼
      n8n  (deterministic workflow engine, NOT in this repo)
        │  1. Alert Builder node — extracts IOCs, builds a TheHive alert body
        │  2. Creates the alert + observables in TheHive
        │  3. Fetches iTop asset context
        │  4. POST /triage → agent-service, with just {thehive_alert_id,
        │     raw_alert, asset_context}
        ▼
   agent-service (this repo)
        │  fetches the rest itself from TheHive (alert + Cortex reports),
        │  builds a CanonicalAlert, runs it through a 3-agent LangGraph
        │  pipeline, returns a TriageResult
        ▼
      n8n  (again) — reads TriageResult.action and performs the actual
             TheHive case action: create case / close as FP / merge / escalate
```

The problem it solves: SOC analysts are flooded with alerts, most of which
are false positives or noise. This service reads a raw detection, correlates
it against existing open cases, gathers supporting evidence (threat intel,
asset context, telemetry, historical case data), and produces a structured
verdict (`true_positive` / `false_positive` / `needs_review`) with a severity,
a MITRE ATT&CK mapping, and a recommended case action — so a human (or,
eventually, an automated downstream step) can act on it without re-doing that
investigation from scratch. It never writes back to TheHive/iTop/Elasticsearch
itself as part of the automated pipeline — that stays n8n's job (see §4, §9).

---

## 2. Current state

**Built and working (against the local test suite; no live infra required to
run tests):**
- Full 3-agent pipeline (perceive → investigate → analyze) wired end to end
  through `graph.py`, invoked from `main.py`'s `/triage` route.
- Deterministic alert normalization (`alert_builder.py`) with confirmed
  per-engine structured extraction (Sigma via `event_data`, Suricata via
  top-level network fields, YARA via top-level file fields) plus regex
  fallbacks.
- Gate 0 Redis-based dedup (optional — no-ops cleanly if `REDIS_URL` unset).
- Detection-rule lookup rewritten to query Elasticsearch's `so-detection`
  index directly (see §5, §8) instead of the filesystem.
- FP-history tracking: a local SQLite counter (`tools/fp_tracking.py`) with
  two time windows (24h / 30d, per the AACT research cited in the code),
  plus a conditional TheHive query gated in code, not just prompt text.
- All three read-only tool integrations (TheHive, Cortex, iTop, Elasticsearch,
  Qdrant, so-detection ES index) implemented as plain Python functions,
  wrapped as LangChain `@tool`s, split into two non-overlapping lists
  (`PERCEPTION_TOOLS`, `INVESTIGATION_TOOLS`) with a module-level `assert` in
  `tools/registry.py` enforcing zero overlap.
- A post-approval case-action module (`nodes/case_action.py`) exists but is
  **not wired into the graph** — see §9.

**Tested:** `pytest tests/ -v` → **154 passed, 0 failed** (verified by running
it directly during this read-through, not taken from a prior log). Coverage
spans schemas, alert_builder, all 5 graph nodes, graph routing, all prompt
builders, detection_rules, fp_tracking, qdrant, and two full end-to-end
`/triage` round trips (`test_e2e.py`) with every external call mocked
(TheHive fetch, both ReAct agents' LLM calls, Agent 3's direct LLM call). No
test in the suite makes a real network call or touches a real LLM. See §9 for
which modules have **no** direct test coverage.

**Committed and pushed:** branch `worktree-twinkly-hugging-hennessy`, HEAD at
commit `2ca7a44` ("Rewrite detection_rule_lookup to query Elasticsearch
so-detection index"), tracking `origin/worktree-twinkly-hugging-hennessy` on
`https://github.com/Achref88MANSOURI/SOC-3s.git`, in sync with the remote (no
ahead/behind). Working tree clean before this document was added. Recent
history on this branch: Phase A (alert_builder event_data fix) → Phase B
(detection_rules Suricata/YARA extension) → Phase C (tool-list split) → Phase
G pulled forward (FP tracking) → Phase D (prompt updates) → Phase E/F
(cleanup + validation) → pre-Tier-0 fix (tool-call budget 6→7) → this
session's Elasticsearch rewrite of `detection_rule_lookup`. The main branch
(`main`) is a separate, earlier line of history not merged with this one as
of this writing.

**Not yet done / explicitly out of scope so far:** live smoke testing against
real Security Onion/TheHive/Cortex/iTop/Elasticsearch traffic (everything
above is verified only against mocks and unit fixtures); the n8n workflow
update described in `N8N-INTEGRATION.md` (documentation only, nothing applied
to a live n8n instance); wiring `case_action.py` into the graph.

---

## 3. Pipeline flow

Exact sequence for a request that reaches `/triage`:

1. **`POST /triage`** (`main.py`) receives `AlertWebhookPayload` —
   `{thehive_alert_id, raw_alert, asset_context}`. This is intentionally slim;
   n8n has already created the TheHive alert and attached observables before
   calling this endpoint.
2. **TheHive fetch** — `tools/thehive.py::get_full_alert_with_analysis(thehive_alert_id)`
   fetches the alert plus its observables, requesting Cortex analyzer reports
   via TheHive's `extraData` mechanism (two separate `/v1/query` calls,
   merged — TheHive 5.6.1 rejected a combined multi-query with
   `error.expected.jsarray`, confirmed live). Returns `None` gracefully if
   the alert can't be found (no raise).
3. **`alert_builder.build_canonical_alert(raw_alert, hive_alert, asset_context, thehive_alert_id)`**
   — pure Python, no LLM. Deterministic best-effort assembly of a
   `CanonicalAlert`: parses rule identity, host, user, process, network,
   file, and observables using per-engine structured extraction first
   (Sigma's `event_data.*`, Suricata's top-level `source`/`destination`,
   YARA's top-level `file`), falling back to regex-over-`description` parsing
   only when structured fields are absent. Every extractor degrades to
   `None`/empty rather than raising. Also builds `CortexResult` entries from
   any Cortex reports already attached to TheHive observables.
4. **`graph.invoke(initial_state)`** — a compiled `langgraph.graph.StateGraph`
   with five nodes, entry point `gate0`:

   ```
   gate0 --(deduplicated)--> format_output --> END
     │
     └--(anything else)--> perceive --(deduplicated)--> format_output --> END
                              │
                              └--(new | merge)--> investigate --> analyze --> format_output --> END
   ```

   - **`gate0` (`nodes/perceive.py::gate0_dedup`)** — pure Python. Computes
     `sha256(rule.uuid + host + user [+ up to 3 sorted external IPs])`,
     checks/sets it in Redis with a `DEDUP_WINDOW_SECONDS` TTL (default 300s).
     If `REDIS_URL` is unset, always returns "not a duplicate" — dedup is
     opt-in infrastructure, never a hard dependency.
   - **`perceive` (Agent 1)** — see §4. Skips entirely if gate0 already
     flagged a duplicate.
   - **`investigate` (Agent 2)** — see §4. Only reached if `mode` is `new` or
     `merge`.
   - **`analyze` (Agent 3)** — see §4. Always follows `investigate`.
   - **`format_output` (`nodes/format_output.py`)** — pure Python, the only
     place severity is computed. Three distinct output shapes depending on
     path taken (dedup short-circuit / merge delta / full new-alert verdict).
     For the full-verdict path, looks up `SEVERITY_TABLE[(likelihood,
     impact_if_true)]` (16-entry table, `unlikely`..`near_certain` ×
     `minor`..`critical`) and calls
     `tools/fp_tracking.record_triage_outcome()` to write one row to the
     local SQLite FP counter — unconditionally, on every completed triage,
     not gated on any human-approval step.
5. **Response** — `main.py` pulls `final_state["triage_result"]` and returns
   it as the `TriageResult` response model. If the graph somehow produces no
   `triage_result` at all, `main.py` raises `HTTPException(500)`; any other
   uncaught exception in the route is also caught and turned into a 500 with
   the error message (never left to crash the ASGI worker).

---

## 4. Agent capabilities

### Agent 1 — Perceive (`nodes/perceive.py::perceive`)
- **Tools:** the exact `PERCEPTION_TOOLS` list from `tools/registry.py` (6):
  `get_fp_signal`, `thehive_fp_history`, `detection_rule_lookup`,
  `qdrant_retrieve_mitre`, `thehive_open_cases`, `get_case_full`.
- **LLM call:** `langgraph.prebuilt.create_react_agent` (a ReAct tool-calling
  loop) over `ChatOpenAI` pointed at `settings.llm_base_url`/`llm_model`
  (an OpenAI-compatible endpoint — the deployment target is Ollama serving
  `qwen3:30b-a3b`, per `config.py`/`SOC-3s-ARCHITECTURE-v3-final.md` §12, not
  independently re-verified by this read-through). `temperature=0.0`.
  `recursion_limit = PERCEPTION_MAX_TOOL_CALLS * 4 + 15` where
  `PERCEPTION_MAX_TOOL_CALLS = 7` (bumped from 6 in the pre-Tier-0 fix to
  leave slack for the prompt's own "retry once on wrong parameter" rule).
- **Produces:** `mitre_mapping: list[MitreMapping]` and a `CorrelationResult`
  (`action`: `new`/`merge`/`deduplicated`, `mode`, `merge_into_case`,
  `existing_case_context`, `reason`, `confidence`). Sets `state["mode"]`.
- **On failure:** two independent fallback layers. (a) If the ReAct agent
  raises (LLM unreachable, etc.) or its final message isn't parseable JSON,
  falls back to `_fallback_deterministic()` — the same entity-match
  (`search_open_cases` by observable/host/user) and kill-chain-progression
  logic (technique→tactic lookup via a hardcoded `TECHNIQUE_TO_TACTIC` table
  and `TACTIC_ORDER` list, checking whether the alert's tactic index exceeds
  the case's) that the pre-LLM `correlate.py` used to run. (b) The
  deterministic fallback itself never raises; it degrades to `mode="new"`,
  `mitre_mapping=[]` if nothing else matches.

### Agent 2 — Investigate (`nodes/investigate.py::investigate`)
- **Tools:** the exact `INVESTIGATION_TOOLS` list (5): `thehive_search_closed`,
  `elasticsearch_query`, `itop_asset_lookup`, `qdrant_retrieve`,
  `cortex_analyze`. No overlap with `PERCEPTION_TOOLS` (enforced by an
  `assert` at import time in `tools/registry.py`).
- **LLM call:** same `create_react_agent`/`ChatOpenAI` pattern as Agent 1, a
  separate instance. `recursion_limit = max_calls * 4 + 15` where
  `max_calls` is `settings.max_tool_calls_new` (default 8) for `mode=="new"`
  or `settings.max_tool_calls_merge` (default 5) for `mode=="merge"`.
- **Produces:** `EvidencePackage` (mode `new`) or `DeltaEvidence` (mode
  `merge`), plus an `investigation_trace: list[InvestigationTraceEntry]`
  built by pairing each `AIMessage.tool_calls` entry with its matching
  `ToolMessage` by call ID.
- **On failure:** if the agent's final message doesn't parse as JSON,
  `_build_from_tool_results()` reconstructs a partial evidence dict directly
  from the raw tool-call results in the message history (bucketing by tool
  name: `itop_asset_lookup`→asset_context, `cortex_analyze`→threat_intel,
  `qdrant_retrieve`→historical_context, `elasticsearch_query`→temporal_context,
  `thehive_search_closed`→historical_context) rather than failing the
  request. If the agent invocation itself raises, `_fallback_state()`
  produces a minimal `EvidencePackage`/`DeltaEvidence` carrying only the
  pre-existing Cortex results Agent 1 already had and an
  `investigation_gaps` note naming the error — never a 500.
- Also guarantees pre-fetched Cortex results (from TheHive, before the agent
  ran) survive into the final evidence even if the LLM's JSON output doesn't
  echo them back (`_merge_cortex_results`, dedup by observable, agent's own
  finding wins on conflict).

### Agent 3 — Analyze (`nodes/analyze.py::analyze`)
- **Tools:** none. A single direct `ChatOpenAI.invoke()` call, no
  tool-calling loop.
- **Never sees raw evidence** — only `_summarize_evidence()`'s truncated view
  (threat-intel details capped at 300 chars, counts instead of full lists for
  related alerts/past cases) plus Agent 1's `mitre_mapping` as
  `agent1_initial_mitre_mapping` for it to *validate and refine*, not
  blindly pass through (this is a deliberate two-pass design, tested
  explicitly — `test_analyze_final_mitre_mapping_comes_from_agent3_not_agent1`).
- **Produces:** `TriageVerdict` (new mode: `likelihood`, `impact_if_true`,
  `verdict`, its own `mitre_mapping`, `reasoning`, `recommended_action`,
  `summary`) or `DeltaVerdict` (merge mode: `severity_change`,
  `new_mitre_stages`, `scope_change`, `urgency`, `recommended_action`,
  `reasoning`).
- **On failure:** if the LLM's response doesn't contain parseable JSON,
  defaults to a safe `needs_review` verdict (new mode) or `merge_quiet`
  (merge mode) with a reasoning string stating the parse failure — never
  raises, never guesses a verdict.
- A GBNF grammar (`prompts/analyst.py::GBNF_GRAMMAR`) is defined for
  constrained decoding on a llama.cpp-compatible inference server, but
  nothing in `nodes/analyze.py` actually passes it to the LLM call — it's
  exported but unused by the current code path. Unclear from code inspection
  whether the deployed Ollama endpoint supports/uses it at all.

---

## 5. Tool inventory

Every tool wrapped in `tools/registry.py`, what it does, and its verification
status (honest, not aspirational):

| Tool (agent) | Backend module | External system | Auth | Verification status |
|---|---|---|---|---|
| `get_fp_signal` (A1) | `tools/fp_tracking.py` | Local SQLite (`FP_DB_PATH`, default `./data/fp_events.db`) | none (local file) | Fully unit-tested (`tests/test_fp_tracking.py`, 9 tests: schema creation, window correctness, per-rule/host scoping). No live/production data exists in this worktree — `data/` directory doesn't exist on disk here yet. |
| `thehive_fp_history` (A1) | `tools/fp_tracking.py` → `tools/thehive.py::search_fp_history` | TheHive `/v1/query` | Bearer token (`THEHIVE_API_KEY`) | Conditional-gating logic unit-tested; the underlying TheHive query shape (`search_fp_history`) is built on the same **unverified** query convention as `search_open_cases`/`search_closed_cases` below — not confirmed against a live 5.6.1 instance. |
| `detection_rule_lookup` (A1) | `tools/detection_rules.py::get_rule_source` | Elasticsearch `so-detection` index | reuses `tools/elasticsearch.py`'s API-key header | Rewritten this session to query ES directly. Schema/coverage numbers (Sigma 86.5%, Suricata ~50%, YARA 0%) are stated in the code's comments and `SOC-3s-ARCHITECTURE-v3-final.md` §7 as confirmed against the live index, but this read-through did not independently re-verify them (no live ES access from this pass) — 10 unit tests with mocked ES responses pass. |
| `qdrant_retrieve_mitre` (A1) | `tools/qdrant.py::retrieve_mitre` | Qdrant, collection `QDRANT_COLLECTION` (default `triage_kb`), payload-filtered on `collection=mitre_attack` | none configured | Unit-tested with mocked client/embedder. **Not confirmed the live `triage_kb` collection is actually populated with this schema** — see §9's ingestion-script mismatch finding. |
| `thehive_open_cases` (A1) | `tools/thehive.py::search_open_cases` | TheHive `/v1/query` | Bearer token | Query shape (`observable`/`host`/`user` `should` clauses, `status in [Open, InProgress]` filter) is **not directly unit-tested** and not confirmed against the live instance — flagged as unverified in the code's own comments. |
| `get_case_full` (A1) | `tools/thehive.py::get_case_full` | TheHive `/v1/case/{id}` | Bearer token | Directly unit-tested (`tests/test_thehive.py`). |
| `thehive_search_closed` (A2) | `tools/thehive.py::search_closed_cases` | TheHive `/v1/query` | Bearer token | **Not directly unit-tested.** Only exercised indirectly through `test_investigate.py`'s mocked-agent tests. Query shape unverified against live TheHive. |
| `elasticsearch_query` (A2) | `tools/elasticsearch.py` (`query_related_alerts`/`query_process_history`/`query_connection_history`) | Elasticsearch, indices `.ds-logs-detections.alerts-so-*`, `.ds-logs-endpoint.process-*`, `.ds-logs-network.flow-*` | API-key header (optional, `ES_API_KEY`) | **No dedicated test file** (`tools/elasticsearch.py` has zero direct tests). Index name patterns are asserted in code comments/architecture doc, not independently re-verified here. |
| `itop_asset_lookup` (A2) | `tools/itop.py::lookup_asset` | iTop JSON-RPC (`webservices/rest.php`) | `auth_user`/`auth_pwd` in POST body | **No dedicated test file.** |
| `qdrant_retrieve` (A2) | `tools/qdrant.py::retrieve_cve`/`retrieve_playbooks` | Same Qdrant collection, filtered `collection=cve_intel`/`collection=playbooks` | none configured | Unit-tested with mocked client/embedder. Same live-population caveat as `qdrant_retrieve_mitre`. |
| `cortex_analyze` (A2) | `tools/cortex.py::analyze_observable` | Cortex REST API (`analyzer`/`job` endpoints, polls for completion) | Bearer token (`CORTEX_API_KEY`) | **No dedicated test file** for `tools/cortex.py`. Picks VirusTotal first if available, else AbuseIPDB for IPs, else first available analyzer — this selection heuristic is not tested. |

**Non-agent-exposed, write-only functions** in `tools/thehive.py`
(`promote_alert_to_case`, `update_case`, `add_case_comment`,
`update_alert_status`, `add_alert_comment`, `merge_alert_into_case`): used
only by `nodes/case_action.py`, which is itself not wired into the graph (see
§9). Explicitly flagged in the module's own comments as **unverified against
the live TheHive instance** — built from TheHive 5's documented v1 REST shape,
not confirmed via Swagger UI.

**`tools/registry.py` itself:** no dedicated `test_registry.py`, but the
critical invariant (zero overlap between `PERCEPTION_TOOLS` and
`INVESTIGATION_TOOLS`) is enforced by a module-level `assert` that runs on
every import — which every test file that touches these tools exercises
transitively.

---

## 6. Data sources

| Data type | Source | Access path |
|---|---|---|
| Alert metadata / observables / Cortex reports already run | TheHive | `tools/thehive.py::get_full_alert_with_analysis`, called once per triage from `main.py` before the graph runs |
| Detection rule source + MITRE tags (Sigma/Suricata/YARA) | Elasticsearch, index `so-detection` | `tools/detection_rules.py::get_rule_source`, one query on `so_detection.publicId`, Agent 1 only |
| Telemetry — related alerts, process history, connection flows | Elasticsearch, `.ds-logs-*` indices | `tools/elasticsearch.py`, Agent 2 only, via `elasticsearch_query` |
| Threat intel on IOCs | Cortex (pre-fetched by n8n for original observables; Agent 2 can call `cortex_analyze` directly for IOCs discovered mid-investigation) | `tools/cortex.py`, reusing the same TheHive-attached reports where possible per the "Cortex discipline" instruction in `prompts/investigator.py` |
| Asset context (criticality, owner, network zone) | iTop CMDB, plus whatever n8n already attached as `asset_context` on the webhook payload | `tools/itop.py::lookup_asset`, Agent 2 only |
| Knowledge base — MITRE technique inference, CVE lookup, playbooks | Qdrant, single collection `triage_kb` with a `collection` payload discriminator | `tools/qdrant.py`; MITRE search (`retrieve_mitre`) is Agent 1-exclusive, CVE/playbook search (`retrieve_cve`/`retrieve_playbooks`) is Agent 2-exclusive |
| False-positive history for this rule+host combo | Local SQLite (`fp_events.db`) + conditional TheHive query for detailed past reasoning | `tools/fp_tracking.py`, Agent 1 only, checked first in the tool-call order |
| Open/closed case correlation | TheHive `/v1/query` | `tools/thehive.py::search_open_cases` (Agent 1) / `search_closed_cases` (Agent 2) |

---

## 7. Technology stack

| Component | Confirmed address / detail | Access method |
|---|---|---|
| LLM | `qwen3:30b-a3b` via an OpenAI-compatible endpoint (`LLM_BASE_URL`/`LLM_MODEL` in `.env`) — per architecture doc, Ollama on CPU (16 cores, 64GB RAM); not independently re-verified live in this pass | `langchain_openai.ChatOpenAI`, `temperature=0.0` everywhere it's used |
| Agent framework | LangGraph (`langgraph.graph.StateGraph`, `langgraph.prebuilt.create_react_agent`) + LangChain (`langchain_core.tools`) | Python library, no separate service |
| Vector DB | Qdrant, `QDRANT_URL` (default `http://localhost:6333`), single collection `QDRANT_COLLECTION` (default `triage_kb`) | `qdrant_client.QdrantClient`, `sentence-transformers` (`QDRANT_EMBEDDING_MODEL`, default `BAAI/bge-m3`, 1024-dim) for query-time embedding |
| Detection rule source | Elasticsearch index `so-detection` (74,888 docs at time of the rewrite that produced this state — not re-confirmed live in this pass) | Reuses `tools/elasticsearch.py`'s `_es_post`/`_headers` (raw `requests`, optional `Authorization: ApiKey`) |
| TheHive | `THEHIVE_URL`, version 5.6.1 per code comments (verified in an earlier session, not re-verified here) | Raw `requests`, Bearer token, `/api/v1/*` |
| Elasticsearch (telemetry) | `ES_URL` | Raw `requests`, optional API-key header |
| Cortex | `CORTEX_URL` | Raw `requests`, Bearer token, analyzer-run + poll-for-report pattern |
| iTop | `ITOP_URL` | Raw `requests`, iTop's own JSON-RPC-over-POST convention (`webservices/rest.php?version=1.3`) |
| FP tracking | Local SQLite, `FP_DB_PATH` (default `./data/fp_events.db`) | `sqlite3` stdlib, one table `fp_events` with a composite index on `(rule_uuid, host, triage_timestamp)` |
| Dedup | Redis, `REDIS_URL` (optional, unset = disabled) | `redis` client, imported lazily inside `_check_dedup` so the dependency isn't required when Redis isn't used |
| Web framework | FastAPI + `uvicorn` | `POST /triage`, `GET /health` |
| Case writes (future) | TheHive REST, same client as reads | Not invoked by the automated pipeline (see §9) |

---

## 8. What was tried and reverted

- **Kibana Security-alert integration** — a `query_kibana_alerts` tool and a
  parallel Kibana ElastAlert trigger were prototyped and evaluated against
  live data (188,877 docs in `.alerts-security.alerts-default`, confirmed).
  Reverted: coverage gaps (many rule types have empty `threat` fields),
  endpoint-only relevance (a Suricata alert would almost never find anything
  there), and no incremental threat-intel value beyond MITRE rule metadata
  that other sources already cover. Security Onion's own alerts remain the
  sole trigger source.
- **`cortex-mcp`** — built in full (3 tools, prompt updates, 14 tests, all
  green) against a stdio-transport MCP server. Reverted after discovering
  `cortex-mcp` hardcodes `StdioServerTransport` with no HTTP/SSE mode, and
  agent-service (172.20.24.224) and cortex-mcp (172.20.24.221) run on
  different VMs — stdio can't cross that boundary. Reverted to direct REST
  (`tools/cortex.py`), same selective-invocation behavior preserved.
- **`thehive4py`** — the original architecture draft assumed this SDK; the
  actual implementation uses raw `requests` throughout `tools/thehive.py`.
  Doc corrected to match code, not the other way around.
- **`fastembed` for Qdrant embedding** — an early doc draft assumed
  `fastembed`+`BAAI/bge-small-en`; the live `triage_kb` collection's vectors
  are 1024-dim (`BAAI/bge-m3`), which no `fastembed`-supported model
  produces, so `tools/qdrant.py`'s query path uses raw `sentence-transformers`
  instead. Note: `fastembed` is *still actually used* by
  `scripts/ingest_qdrant.py` — see §9 for why this is now a live
  inconsistency, not a resolved one.
- **Filesystem-based detection rule lookup** — Phase B's `detection_rules.py`
  read Sigma YAML from `SIGMA_RULES_PATH` and scanned Suricata's `all.rules`
  file directly. Superseded this session: the filesystem Sigma path
  (`/opt/so/rules/elastalert/rules/*.yml`) is compiled ElastAlert2 output with
  the MITRE `tags:` field stripped during compilation — it could never yield
  MITRE mappings. Replaced with a single Elasticsearch query against
  Security Onion's `so-detection` index, which holds unmodified native
  source (with tags intact) for all three engines. `SIGMA_RULES_PATH` /
  `SURICATA_RULES_PATH` removed from `config.py`.

---

## 9. Known gaps and open items

**From `CHANGES.md`'s own tracked known-issues list, still open:**
- `requirements-dev.txt` does not exist. `test.sh` (§ "install dependencies")
  will fail on a clean environment as written — confirmed still true; no such
  file exists in the repo. `CLAUDE.md` itself already flags this.
- `Impact`/`Likelihood`/`Severity` Literal type aliases were never added to
  `schemas.py` — harmless (nothing imports them) but noted as still missing.
- `nodes/perceive.py`'s `perceive()` does not re-normalize `CanonicalAlert`
  fields (host/user/network/process) the way the original architecture's §6
  sub-task 2 described — accepted as a known gap by prior explicit user
  decision; Agent 1 takes `alert_builder.py`'s deterministic output as given
  and focuses on MITRE mapping + correlation only.
- **Agent 2's `rule_context` gap** — `detection_rule_lookup` became Agent
  1-exclusive in Phase C, so Agent 2 can no longer independently fetch
  `known_fp_conditions`/`detection_logic` for the rule that fired. Accepted:
  Agent 1's `mitre_mapping[].basis` strings are the load-bearing mechanism
  carrying rule context forward. Flagged to revisit only if live testing
  shows Agent 2 producing poor FP assessments traceably linked to this gap —
  and if so, the stated fix is adding the rule source as a field on the
  handoff, not re-granting Agent 2 a lookup tool (which would reintroduce
  the tool duplication Phase C removed).
- `nodes/case_action.py`'s six TheHive write functions are implemented from
  TheHive 5's documented REST shape but **not verified against the live
  5.6.1 instance** (unlike the read path, which is verified). Only the
  `close_fp` → `"Ignored"` status value has been independently confirmed
  live.
- ES firewall rule (agent-service IP in Security Onion's
  `elasticsearch_rest` hostgroup) — status not confirmed by any session,
  not blocking any code phase but blocking live smoke testing.

**No `TODO`/`FIXME`/`PLACEHOLDER`/`XXX` markers exist anywhere in the `.py`
source** (checked via repo-wide grep) — open items are tracked in
`CHANGES.md` prose instead of inline code markers.

**Zero direct test coverage** (confirmed by checking for a matching
`tests/test_*.py` for every module in `tools/`, `nodes/`, and top-level):
- `tools/cortex.py` — no `test_cortex.py`.
- `tools/elasticsearch.py` — no `test_elasticsearch.py`.
- `tools/itop.py` — no `test_itop.py`.
- `tools/registry.py` — no dedicated test file (the zero-overlap assertion
  is exercised transitively by every other test file's imports, but there's
  no test that would catch a broken tool wrapper signature, for example).
- `config.py` — no direct test (exercised transitively by everything that
  imports it).
- `scripts/ingest_qdrant.py` — no test file at all.

**Partial coverage:** `tools/thehive.py` — `get_full_alert_with_analysis`,
`search_fp_history`, and `get_case_full` are directly tested;
`search_open_cases` and `search_closed_cases` (both load-bearing — Agent 1's
correlation and Agent 2's historical-case lookup both depend on them) have no
direct test and are only exercised indirectly through other modules' mocked
tests.

**Newly found in this read-through, not previously flagged in `CHANGES.md`:**

1. **`scripts/ingest_qdrant.py` and `tools/qdrant.py` are structurally
   incompatible as currently written.** `ingest_qdrant.py` creates **three
   separate named Qdrant collections** (`mitre_attack`, `cve`, `playbooks`),
   each with **384-dimension** vectors produced by `fastembed`'s
   `BAAI/bge-small-en`. `tools/qdrant.py` (the actual runtime query path used
   by both agents) queries a **single collection** (`QDRANT_COLLECTION`,
   default `triage_kb`) with **1024-dimension** vectors produced by
   `sentence-transformers`' `BAAI/bge-m3`, filtered by a payload field
   `collection` whose values are `mitre_attack`, `cve_intel` (not `cve`),
   and `playbooks`. Running `python scripts/ingest_qdrant.py all` as
   documented in `CLAUDE.md`'s Commands section, against a fresh Qdrant
   instance, would **not** populate anything `tools/qdrant.py` can read —
   wrong collection name(s), wrong vector dimension, wrong embedding model,
   and (for CVE) a mismatched discriminator value. `CHANGES.md` (line 311)
   claims `fastembed` is listed in `requirements.txt` but "unused" — that is
   incorrect; `fastembed` **is** used, by `ingest_qdrant.py`, just not by the
   runtime query path. Whatever populated the live `triage_kb` collection
   (referenced as "already deployed and working" in the architecture doc's
   rejected-alternatives table) evidently did not go through this script as
   it exists today — unclear from code inspection how it actually got
   populated. **This should be resolved before relying on
   `qdrant_retrieve_mitre`/`qdrant_retrieve` in a live Tier 0 test**, since
   right now the ingestion script and the query code cannot talk to the same
   data.
2. **`schemas.py`'s `TriageState` TypedDict comment is stale.** It documents
   `raw_alert`/`asset_context`/`thehive_alert_id` as "Webhook path input...
   consumed by `perceive()`", but `nodes/perceive.py` never reads any of
   those three state keys, and `main.py` never populates them in
   `initial_state` either — `alert_builder.py` builds the full
   `CanonicalAlert` *before* the graph even runs, and only `canonical_alert`
   (plus the various result/verdict placeholders) is seeded into
   `initial_state`. These three `TypedDict` fields appear to be dead,
   left over from an earlier design where `perceive()` itself did the
   alert-building.
3. **`SOC-3s-ARCHITECTURE-v3-final.md` §11's tool inventory undercounts
   `PERCEPTION_TOOLS`.** It lists `PERCEPTION_TOOLS = [detection_rule_lookup,
   thehive_open_cases, qdrant_retrieve_mitre, get_fp_signal,
   thehive_fp_history]` — 5 tools, missing `get_case_full` entirely. The
   actual `tools/registry.py` has 6: `get_fp_signal`, `thehive_fp_history`,
   `detection_rule_lookup`, `qdrant_retrieve_mitre`, `thehive_open_cases`,
   `get_case_full`. (§7a of the same doc and the prompt/tests elsewhere
   correctly reference 6 — this is an isolated stale spot in §11.)
4. **`test.sh` references a script that doesn't exist.** Its final echo line
   says "Next: fill in .env, then run `./scripts/smoke_test.sh` against a
   live server" — no `smoke_test.sh` exists anywhere in `scripts/` or the
   repo. Either it was never written or was removed; `test.sh` itself still
   runs and passes up through its own 4 steps (the broken reference is only
   in the trailing suggestion text, not a functional part of the script) —
   except step 2 (`pip install ... requirements-dev.txt`) will fail as noted
   above since that file doesn't exist.
5. **`CHANGES.md`'s "Known issues" list (line 416) still names
   `tools/sigma_rules.py`** in its zero-coverage list — that file was renamed
   to `tools/detection_rules.py` in Phase B and now has 10 tests. Stale
   reference, harmless, but worth a cleanup pass next time `CHANGES.md` gets
   touched.

---

## 10. Tier 0 prerequisites

Tier 0, per the architecture doc, is advisory-only validation: every
`TriageResult` gets attached to the case for a human analyst to review, the
pipeline does not auto-act, and agreement rate is tracked before considering
any tier where the system acts autonomously.

**Done:**
- Full pipeline code path exists and is unit/integration-tested against
  mocks (154/154 passing).
- All read-only tool integrations are implemented.
- Detection-rule lookup now sources from the correct live data (ES
  `so-detection`), fixing what would otherwise have been a silent MITRE-mapping
  gap for every Sigma alert.
- FP-history tracking is wired into every completed triage automatically.
- `n8n`-side contract is documented in `N8N-INTEGRATION.md` (slim payload
  shape, what fields to route on, what nodes to remove).

**Still needed before a live alert can flow through successfully:**
1. **n8n workflow update** — per `N8N-INTEGRATION.md`: point the existing
   POST-to-agent-service node at the new slim `AlertWebhookPayload` shape
   (`thehive_alert_id`, `raw_alert`, `asset_context`), remove the
   per-observable-type Cortex Switch/analyzer nodes (Agent 2 now triggers
   Cortex itself, selectively), remove any separate observable-ID-fetch step
   (agent-service now fetches that itself). Nothing here has been applied to
   a live n8n instance — this is still a documentation-only deliverable as
   of this state.
2. **Fix the Qdrant ingestion/query mismatch** (§9, item 1) — otherwise
   `qdrant_retrieve_mitre` and `qdrant_retrieve` will silently return `[]`
   against a freshly-ingested collection, or continue relying on whatever
   populated the live `triage_kb` collection outside this script.
3. **Confirm the ES firewall hostgroup** includes the agent-service host —
   `elasticsearch_query` and `detection_rule_lookup` both depend on reaching
   Elasticsearch directly.
4. **Verify TheHive write-path endpoints live** if `case_action.py` is ever
   wired in — not required for Tier 0 itself (Tier 0 is advisory-only, no
   auto-action), but n8n's *own* write nodes (which remain the actual actor
   in Tier 0) should be spot-checked against the current `TriageResult`
   field names per `N8N-INTEGRATION.md` §6's testing checklist.
5. **Confirm `.env` on the actual deployment host** has all required vars —
   this worktree only has them because `python-dotenv` walks up to the main
   checkout's `.env`; a real deployment needs its own.

**What the first real-alert test should look like:** trigger one real,
low-severity Security Onion alert (a Sigma alert is the best first case,
since it exercises the `event_data` structured-extraction path and the newly
rewritten `detection_rule_lookup`) through the full n8n → agent-service →
n8n loop with `action` routing set to *advisory-only* (log/attach the
`TriageResult`, do not let n8n act on it yet). Confirm: `/health` responds
first; the `/triage` POST body actually matches the shape `N8N-INTEGRATION.md`
§1/§2 describes (verify via n8n's execution log, not assumption);
`/triage` returns `200` with a well-formed `TriageResult`, not a `500`;
`investigation_trace` shows real tool calls (not an empty list, which would
indicate the ReAct agent produced no tool calls at all — a red flag);
`mitre_mapping` is non-empty if the fired rule is Sigma-based (this is the
specific thing this session's rewrite was meant to fix). Then repeat with one
Suricata and one YARA alert to exercise the other two `investigation_profile`
branches before broadening to real traffic volume.

---

## 11. File tree

```
.
├── alert_builder.py            Deterministic (non-LLM) CanonicalAlert assembly from n8n's raw_alert + TheHive fetch
├── CHANGES.md                  Running development log — phase-by-phase history, decisions, test counts, known issues
├── CLAUDE.md                   Project instructions for Claude Code — architecture summary, commands, invariants
├── config.py                   Loads .env, fails fast on missing required vars, exposes Settings + module-level constants
├── graph.py                    LangGraph StateGraph definition — 5 nodes, gate0/perceive conditional routing
├── main.py                     FastAPI app — POST /triage, GET /health
├── N8N-INTEGRATION.md          Documentation-only: required n8n workflow changes to match the current /triage contract
├── nodes/
│   ├── __init__.py             Empty
│   ├── analyze.py              Agent 3 — single LLM call, produces TriageVerdict/DeltaVerdict, safe fallback on parse failure
│   ├── case_action.py          Post-approval TheHive write path (create/close/merge case actions) — NOT wired into graph.py
│   ├── format_output.py        Pure Python — severity lookup table, builds final TriageResult, records FP outcome
│   ├── investigate.py          Agent 2 — ReAct loop over INVESTIGATION_TOOLS, produces EvidencePackage/DeltaEvidence
│   └── perceive.py             Gate 0 dedup (pure Python) + Agent 1 — ReAct loop over PERCEPTION_TOOLS, MITRE mapping + correlation
├── prompts/
│   ├── __init__.py             Empty
│   ├── analyst.py               Agent 3's system prompt, output JSON schemas, GBNF grammar (defined but unused by analyze.py)
│   ├── investigator.py          Agent 2's system prompt — tool docs, per-profile investigation focus, Cortex discipline
│   └── perceiver.py             Agent 1's system prompt — all 6 PERCEPTION_TOOLS documented, explicit tool call order, FP guardrail
├── requirements.txt             Python dependencies (includes fastembed, used only by scripts/ingest_qdrant.py — see §9)
├── schemas.py                   All Pydantic models + the LangGraph TriageState TypedDict, single file
├── scripts/
│   ├── __init__.py              Empty
│   └── ingest_qdrant.py         Standalone CLI to populate Qdrant — currently mismatched with tools/qdrant.py's schema, see §9
├── SOC-3s-ARCHITECTURE-v3-final.md  Design/architecture reference — current, but with drift noted in §9 above
├── test.sh                      Local static-check runner: syntax check, install deps, pytest, import/route-registration check
├── tests/
│   ├── __init__.py               Empty
│   ├── conftest.py               Autouse fixture isolating every test's FP_DB_PATH to a tmp_path
│   ├── test_alert_builder.py     11 tests — per-engine structured extraction, regex fallback, observable mislabel correction
│   ├── test_analyze.py           11 tests — JSON extraction, evidence summarization, Agent-3-not-Agent-1 mapping assertion
│   ├── test_case_action.py       11 tests — all 4 case actions, approval gate, error paths
│   ├── test_detection_rules.py   10 tests — ES-mocked, all Sigma tag namespaces, Suricata with/without MITRE, YARA, errors
│   ├── test_e2e.py               2 tests — full /triage round trip, all external calls mocked, dedup short-circuit
│   ├── test_format_output.py     12 tests — severity table coverage, all 3 output shapes, FP-outcome recording
│   ├── test_fp_tracking.py       9 tests — schema creation, two-window correctness, conditional TheHive query gating
│   ├── test_graph.py             6 tests — routing functions, node registration
│   ├── test_investigate.py       12 tests — JSON parsing, tool-result fallback, cortex-result merging, trace extraction
│   ├── test_perceive.py          12 tests — kill-chain logic, gate0 dedup, agent JSON parsing, deterministic fallback
│   ├── test_perceiver_prompt.py  7 tests — all 6 tools documented, call order, FP guardrail, no Kibana references
│   ├── test_prompts.py           11 tests — investigator/analyst prompt content, forbidden-tool absence, profile blocks
│   ├── test_qdrant.py            4 tests — metadata unwrapping per collection, exception swallowing
│   ├── test_schemas.py           14 tests — Pydantic model construction/defaults for every schema
│   └── test_thehive.py           9 tests — alert+observable merge, FP history, case fetch, error paths
├── tools/
│   ├── __init__.py               Empty
│   ├── cortex.py                 Cortex client — analyzer selection, run+poll, taxonomy summarization. No dedicated tests.
│   ├── detection_rules.py        get_rule_source() — single ES query on so-detection, per-language MITRE parsing
│   ├── elasticsearch.py          Shared ES client (_es_post/_headers) + telemetry queries (alerts/process/connections). No dedicated tests.
│   ├── fp_tracking.py            SQLite FP-history counter — get_fp_signal, thehive_fp_history, record_triage_outcome
│   ├── itop.py                   iTop JSON-RPC asset lookup. No dedicated tests.
│   ├── qdrant.py                 Qdrant client wrapper — retrieve_mitre/retrieve_cve/retrieve_playbooks, single-collection+discriminator pattern
│   ├── registry.py                @tool wrappers for every backend function; PERCEPTION_TOOLS/INVESTIGATION_TOOLS split + zero-overlap assert
│   └── thehive.py                 TheHive REST client — reads (used by pipeline) + writes (used only by case_action.py, unverified live)
└── .gitignore                    .env, __pycache__/, *.pyc, .venv/, data/*.db
```

Not present in the repo despite being referenced elsewhere: `.env` (gitignored,
loaded from the parent checkout in this worktree), `requirements-dev.txt`
(referenced by `test.sh`, never created — see §9), `scripts/smoke_test.sh`
(referenced by `test.sh`'s trailing suggestion text, never created — see §9),
`data/` directory (created on first write by `tools/fp_tracking.py`'s
`_connect()`, doesn't exist yet in this worktree).
