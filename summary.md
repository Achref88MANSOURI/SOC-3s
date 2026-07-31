# SOC Triage Agent — Complete Project Summary

## Overview

A **LangGraph-powered FastAPI service** that automates SOC alert triage. Receives a normalized security alert (`CanonicalAlert`) from an n8n workflow, runs it through a 4-node state machine (correlate → investigate → analyze → format_output), and returns a structured `TriageResult` with verdict, severity, MITRE mapping, reasoning, and recommended action.

**Input:** `POST /triage` with `CanonicalAlert` JSON  
**Output:** `TriageResult` JSON (action: create_case | close_fp | needs_review | merge_quiet | merge_and_retier | deduplicated)  
**Health:** `GET /health` returns `{"status": "ok", "timestamp": "...", "service": "agent-service"}`  

---

## File Tree

```
agent-service/
├── main.py                     # FastAPI app, POST /triage + GET /health
├── graph.py                    # LangGraph StateGraph wiring (4 nodes + conditional edge)
├── config.py                   # Env var loader via python-dotenv, typed Settings dataclass
├── schemas.py                  # All Pydantic models + TriageState TypedDict
├── requirements.txt            # Python dependencies
├── .env                        # Credentials (gitignored)
├── .gitignore
├── alert-sample.json           # Sample raw Security Onion alert for testing
├── test.sh                     # Empty placeholder
├── CONTEXT.md                  # Architecture reference (this document's source)
├── CONTEXT.md.save             # Earlier version of CONTEXT.md
├── preview.md                  # Shorter project overview
│
├── nodes/
│   ├── __init__.py
│   ├── correlate.py            # Check 1: Redis dedup, Check 2: entity match, Check 3: story match
│   ├── investigate.py          # Agent 1: ReAct LLM with 6 tools, mode-aware (new/merge)
│   ├── analyze.py              # Agent 2: single LLM call, no tools, verdict/delta assessment
│   └── format_output.py        # Severity lookup table + TriageResult builder
│
├── tools/
│   ├── __init__.py
│   ├── registry.py             # LangChain @tool wrappers for all 6 tools
│   ├── cortex.py               # Cortex TI analyzer (auto-picks VirusTotal/AbuseIPDB)
│   ├── itop.py                 # iTop CMDB asset lookup (JSON-RPC over HTTP)
│   ├── thehive.py              # TheHive case search (open/closed/full)
│   ├── elasticsearch.py        # ES queries: related alerts, process history, connection flows
│   ├── sigma_rules.py          # Read Sigma rule YAML from filesystem by UUID
│   └── qdrant.py               # Qdrant vector search (MITRE ATT&CK, playbooks, CVE)
│
├── prompts/
│   ├── __init__.py
│   ├── investigator.py         # Agent 1 system prompt + 5 investigation profiles
│   └── analyst.py              # Agent 2 system prompt + JSON schemas + GBNF grammar
│
├── scripts/
│   ├── __init__.py
│   └── ingest_qdrant.py        # Populate Qdrant: MITRE (STIX), CVE (NVD), playbooks (local)
│
└── tests/
    ├── __init__.py
    ├── test_schemas.py         # 11 Pydantic model tests
    ├── test_graph.py           # LangGraph routing + node presence
    ├── test_correlate.py       # Dedup/entity/story match + kill-chain logic
    ├── test_format_output.py   # Severity table (16 cells) + 4 code paths
    ├── test_analyze.py         # JSON extraction (7 edge cases) + evidence summarization
    └── test_prompts.py         # Investigator profiles + analyst modes + schemas
```

---

## Pipeline Architecture

```
POST /triage (CanonicalAlert)
    │
    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ NODE 1: CORRELATE  (nodes/correlate.py — pure Python, no LLM)       │
│                                                                     │
│  Check 1 — Redis Fingerprint Dedup                                  │
│    key = sha256(rule.uuid + host.hostname + user.name + ips[:3])    │
│    window = 300 seconds (configurable via DEDUP_WINDOW_SECONDS)     │
│    hit → {action: "deduplicated"} → skip to format_output           │
│    miss → SETEX key with TTL, continue                              │
│    If REDIS_URL not set → skip check                                │
│                                                                     │
│  Check 2 — Entity Match (TheHive)                                   │
│    search_open_cases(observables, hostname, username)               │
│    match on ANY shared observable/host/user with open case          │
│    hit → {action: "merge", mode: "merge", merge_into_case: id}      │
│                                                                     │
│  Check 3 — MITRE Kill-Chain Story Match                             │
│    Extract techniques from alert's Sigma rule tags (attack.Txxxx)   │
│    Search open cases on same host                                   │
│    Check if alert introduces a later-stage tactic vs case tactics    │
│    Uses 61-technique→tactic mapping across 14 ordered tactics       │
│    hit → {action: "merge", mode: "merge", reason: "kill_chain"}     │
│                                                                     │
│  No match → {action: "new", mode: "new"}                            │
└─────────────────────────────────────────────────────────────────────┘
    │                │
    │ deduplicated   │ new / merge
    ▼                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ NODE 2: INVESTIGATE  (nodes/investigate.py — Agent 1, ReAct + LLM)  │
│                                                                     │
│  Uses LangGraph create_react_agent with ChatOpenAI (temp=0)         │
│  System prompt from prompts/investigator.py (profile-aware)         │
│                                                                     │
│  Mode NEW:                                                          │
│    - Build complete evidence picture from scratch                   │
│    - Budget: max 8 tool calls (configurable: MAX_TOOL_CALLS_NEW)    │
│    - Output: EvidencePackage{}                                       │
│                                                                     │
│  Mode MERGE:                                                        │
│    - Investigate only what this alert ADDS to existing case         │
│    - Receives existing_case_context in human message                │
│    - Budget: max 5 tool calls (configurable: MAX_TOOL_CALLS_MERGE)  │
│    - Output: DeltaEvidence{}                                         │
│                                                                     │
│  Agent output is parsed as JSON. If unparseable:                    │
│    - Fallback: build evidence directly from tool call results        │
│    - Extract sigma_rule_lookup → rule_context                        │
│    - Extract itop_asset_lookup → asset_context                       │
│    - Extract cortex_analyze → threat_intel[]                         │
│    - Extract elasticsearch_query → temporal_context                  │
│    - Extract qdrant_retrieve / thehive_search → historical_context   │
│                                                                     │
│  On agent crash → fallback with investigation_gaps filled           │
└─────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ NODE 3: ANALYZE  (nodes/analyze.py — Agent 2, single LLM call)      │
│                                                                     │
│  NO TOOLS — pure reasoning only (prompt injection firewall)         │
│  Summarizes evidence before LLM call (truncates to typed fields)    │
│  System prompt from prompts/analyst.py                               │
│                                                                     │
│  Mode NEW → TriageVerdict:                                           │
│    likelihood:  unlikely | possible | likely | near_certain         │
│    impact_if_true: minor | moderate | severe | critical             │
│    verdict:      true_positive | false_positive | needs_review      │
│    mitre_mapping: [{tactic, technique, sub_technique, confidence,   │
│                     basis}]                                         │
│    reasoning: every claim cites evidence field                      │
│    recommended_action: create_case | close_fp | needs_review        │
│    summary: 3-5 sentence analyst-readable brief                     │
│                                                                     │
│  Mode MERGE → DeltaVerdict:                                          │
│    severity_change: "medium → high" | "no_change"                   │
│    new_mitre_stages: [{tactic, technique}]                           │
│    scope_change: "1 host → 3 hosts" | "no_change"                  │
│    urgency: escalate | routine_merge                                │
│    recommended_action: merge_and_retier | merge_quiet               │
│    reasoning: cites delta_evidence fields                           │
│                                                                     │
│  On JSON parse failure → fallback to needs_review (new) or          │
│    merge_quiet (merge)                                              │
└─────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ NODE 4: FORMAT_OUTPUT  (nodes/format_output.py — pure Python)       │
│                                                                     │
│  SEVERITY LOOKUP TABLE (likelihood × impact_if_true → severity):    │
│                  minor    moderate   severe    critical              │
│  unlikely          low      low        medium    medium              │
│  possible          low      medium     high      high                │
│  likely            medium   high       high      critical            │
│  near_certain      medium   high       critical  critical            │
│                                                                     │
│  DEDUPLICATED path: action=deduplicated, no verdict/severity        │
│  NEW path: lookup severity, build full TriageResult                 │
│  MERGE path: severity from delta.severity_change, urgency/action    │
│  NO VERDICT path: action=needs_review                               │
│                                                                     │
│  Returns TriageResult{} to n8n                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## File-by-File Detail

### `main.py` — FastAPI Application Entry Point

- **`GET /health`** → `HealthResponse{status, timestamp, service}`. Simple liveness check.
- **`POST /triage`** → Accepts `CanonicalAlert`, builds initial `TriageState`, calls `graph.invoke(initial_state)`, returns `TriageResult`. Catches all exceptions, returns 500 with detail. Logs alert_id, rule, profile on entry; logs action + verdict on completion.

### `graph.py` — LangGraph State Machine

- **`TriageState`** TypedDict with fields: `canonical_alert`, `mode`, `correlation_result`, `existing_case_context`, `evidence_package`, `delta_evidence`, `triage_verdict`, `delta_verdict`, `triage_result`.
- **`_route_after_correlate(state)`** — If `correlation_result.action == "deduplicated"`, route directly to `format_output` (skip both agents). Otherwise route to `investigate`.
- **4 nodes**: `correlate` → conditional → `investigate` → `analyze` → `format_output` → END.
- Compiled graph stored as `graph` variable, imported by `main.py`.

### `config.py` — Environment Configuration

- **`Settings` dataclass** with all typed config fields. Loaded via `python-dotenv`.
- **Required vars** (will raise RuntimeError if missing):
  - `CORTEX_URL`, `CORTEX_API_KEY` — Cortex TI analyzer
  - `THEHIVE_URL`, `THEHIVE_API_KEY` — TheHive case management
  - `ITOP_URL`, `ITOP_USER`, `ITOP_KEY` — iTop CMDB
  - `ES_URL`, `LLM_BASE_URL`, `LLM_MODEL` — Elasticsearch + LLM endpoint
- **Optional vars**: `ES_API_KEY`, `LLM_API_KEY`, `QDRANT_URL`, `REDIS_URL`, `SIGMA_RULES_PATH`, `MAX_TOOL_CALLS_NEW` (default 8), `MAX_TOOL_CALLS_MERGE` (default 5), `DEDUP_WINDOW_SECONDS` (default 300).
- Exports all config values as module-level constants for easy import.
- `__main__` block prints masked config for debugging.

### `schemas.py` — All Pydantic Models

| Model | Key Fields | Used By |
|-------|-----------|---------|
| `CanonicalAlert` | alert_id, timestamp, source_engine, investigation_profile, rule, host, user, network, process, file, observables, thehive_alert_id, thehive_observable_ids | API input |
| `Rule` | name, uuid, native_severity, category, product | Embedded in CanonicalAlert |
| `Host` | hostname, ip[], os{} | Embedded in CanonicalAlert |
| `User` | name, id | Embedded in CanonicalAlert |
| `Network` | src_ip, dst_ip, src_port, dst_port, protocol, bytes_total, packets_total | Embedded in CanonicalAlert |
| `Process` | pid, name, path, command_line, parent_pid, parent_name | Embedded in CanonicalAlert |
| `File` | name, path, size, mime_type | Embedded in CanonicalAlert |
| `HashBundle` | md5[], sha1[], sha256[], sha512[] | Embedded in Observables |
| `Observables` | external_ips[], domains[], urls[], hashes | Embedded in CanonicalAlert |
| `CortexResult` | observable, type, verdict, score, details, analyzer, raw | EvidencePackage.threat_intel |
| `EvidencePackage` | rule_context{}, asset_context{}, threat_intel[], temporal_context{}, historical_context{}, investigation_gaps[], investigation_trace[] | Agent 1 output (new mode) |
| `DeltaEvidence` | new_iocs[], new_hosts[], new_users[], new_kill_chain_stages[], changed_ti_verdicts[], additional_context{}, investigation_gaps[], investigation_trace[] | Agent 1 output (merge mode) |
| `MitreMapping` | tactic, technique, sub_technique?, confidence, basis | TriageVerdict.mitre_mapping |
| `TriageVerdict` | likelihood, impact_if_true, verdict, mitre_mapping[], reasoning, recommended_action, summary | Agent 2 output (new mode) |
| `DeltaVerdict` | severity_change, new_mitre_stages[], scope_change, urgency, recommended_action, reasoning | Agent 2 output (merge mode) |
| `CorrelationResult` | action, mode, merge_into_case?, existing_case_context?, reason | Node 1 output |
| `TriageResult` | alert_id, action, verdict?, severity?, likelihood?, impact_if_true?, mitre_mapping[], reasoning, summary, merge_into_case?, severity_change?, urgency?, evidence_package{}, investigation_trace[], correlation_result? | API response |
| `InvestigationTraceEntry` | tool, params{}, result_summary | Used in EvidencePackage/DeltaEvidence |
| `TriageState` | TypedDict: canonical_alert, mode, correlation_result, existing_case_context, evidence_package, delta_evidence, triage_verdict, delta_verdict, triage_result | LangGraph state |

---

## Nodes (Detailed)

### `nodes/correlate.py` — Correlation Engine

**Function: `correlate(state) -> state`**

3 checks run sequentially. First match wins.

**Check 1: Redis Dedup (`_check_dedup`)**
- Builds fingerprint from `rule.uuid + host.hostname + user.name + sorted(external_ips[:3])`
- Hashes with SHA-256
- If Redis key exists → duplicate (return `is_duplicate=True`)
- If not → store key with TTL of `DEDUP_WINDOW_SECONDS` (default 300s)
- Gracefully handles Redis being unavailable

**Check 2: Entity Match (`_find_merge_candidate`)**
- Collects observables (external_ips + domains)
- Calls `search_open_cases(observables, hostname, username)` on TheHive
- Picks first matching case, returns summary dict with case_id, title, severity, tags, description, host, user, observables, created_at

**Check 3: Story Match (`_find_story_match`)**
- Only if hostname is present
- Extracts MITRE techniques from Sigma rule tags (e.g., `attack.T1566`)
- Searches open cases on same host
- For each case, extracts techniques from case tags
- `_is_kill_chain_progression(alert_techniques, case_techniques)` — checks if any alert tactic index > max case tactic index (meaning attacker is progressing through kill chain)
- Tactic ordering: reconnaissance(0) → resource_development(1) → initial_access(2) → execution(3) → persistence(4) → privilege_escalation(5) → defense_evasion(6) → credential_access(7) → discovery(8) → lateral_movement(9) → collection(10) → command_and_control(11) → exfiltration(12) → impact(13)
- 61 techniques mapped to tactics in `TECHNIQUE_TO_TACTIC` dict

**Key constants:**
- `TACTIC_ORDER` — 14 tactics in kill-chain order
- `TECHNIQUE_TO_TACTIC` — Maps technique IDs (T1078, T1566, T1059...) to tactic names

### `nodes/investigate.py` — Agent 1 (ReAct Investigator)

**Function: `investigate(state) -> state`**

- Creates a `ChatOpenAI` model (temperature=0) pointed at `settings.llm_base_url`
- Creates `create_react_agent` with all 6 tools from `tools.registry.TOOLS`
- Loads system prompt via `build_prompt(profile, mode)` from `prompts/investigator.py`
- Serializes `canonical_alert` as JSON for the human message
- If mode=merge, appends `existing_case_context` JSON to the human message
- Calls `agent.invoke()` with `recursion_limit` = `max_calls * 4 + 15`

**Post-invocation processing:**
1. `_extract_trace(messages)` — Iterates all messages, pairs tool_calls with tool responses, builds `InvestigationTraceEntry[]` list
2. `_get_final_text(messages)` — Gets last AI message that has content but no tool_calls
3. `_try_parse_json(final_text)` — Extracts JSON from markdown fences, finds first `{...}` block
4. If parsed → builds `EvidencePackage` (new) or `DeltaEvidence` (merge)
5. If NOT parsed → `_build_from_tool_results(messages, trace)` — walks all tool messages, extracts evidence from each tool's output directly (rule_context from sigma_rule_lookup, asset_context from itop_asset_lookup, threat_intel from cortex_analyze, temporal_context from elasticsearch_query, historical_context from qdrant_retrieve/thehive_search)
6. On exception → `_fallback_state()` with investigation_gaps filled with error message

### `nodes/analyze.py` — Agent 2 (Analyst LLM)

**Function: `analyze(state) -> state`**

- Creates a `ChatOpenAI` model (temperature=0, max_tokens=1024)
- No tools — just a single LLM call with system + user messages
- Loads system prompt via `build_prompt(mode)` from `prompts/analyst.py`
- Gets output schema via `output_schema(mode)` — provides JSON schema for LLM

**Evidence summarization (`_summarize_evidence`):**
- Extracts key fields from EvidencePackage/DeltaEvidence (not the full data)
- Truncates threat_intel details to 300 chars each
- Counts related alerts (not list contents)
- Counts past cases (not list contents)

**Prompt to LLM:**
- Mode new: evidence_package_summary + schema description
- Mode merge: existing_case_context + delta_evidence + schema description

**Post-LLM processing:**
1. `_extract_json(raw_text)` — Handles markdown fences, extracts first `{...}`, returns None if no valid JSON found
2. If parsed → builds `TriageVerdict(**parsed)` or `DeltaVerdict(**parsed)`
3. If NOT parsed → fallback: needs_review with explanation (new) or merge_quiet with reasoning (merge)

### `nodes/format_output.py` — Output Formatter

**Function: `format_output(state) -> state`**

**Severity table** (`SEVERITY_TABLE`): 16 entries mapping `(likelihood, impact_if_true)` tuples to severity strings. Hardcoded dict — never a model output.

**4 code paths:**
1. **DEDUPLICATED** — `corr.action == "deduplicated"`: Returns `TriageResult` with `action=deduplicated`, no verdict/severity. Includes `correlation_result` in response.
2. **MERGE** — `mode == "merge"` and `delta` exists: Extracts urgency, severity_change, action from `DeltaVerdict`. Parses `severity_change "medium -> high"` to extract new severity. Includes `merge_into_case`, `severity_change`, `urgency` in response.
3. **NEW** — `verdict` is set: Looks up severity from table. Includes full verdict data: likelihood, impact, MITRE mapping, reasoning, summary. Includes `evidence_package` and `investigation_trace`.
4. **NO VERDICT** — fallback: Returns `action=needs_review` with reasoning "No verdict produced by analysis node."

---

## Tools (6 total — all read-only)

### `tools/cortex.py` — Cortex Analyzer

**Function: `analyze_observable(observable_type, observable_value, timeout=180) -> dict`**

Supported types: `ip`, `domain`, `url`, `hash`.

Algorithm:
1. Validate type → return unknown if invalid
2. List available analyzers for that type via `GET /api/analyzer/type/{type}`
3. Pick analyzer: prefer VirusTotal → AbuseIPDB (for IPs) → first available
4. Run analyzer via `POST /api/analyzer/{id}/run`
5. Wait for report via `GET /api/job/{id}/waitreport` (long poll up to `timeout` seconds)
6. Extract taxonomies from job report summary
7. Reduce to worst-case verdict: malicious(90) > suspicious(55) > safe(5) > info(0)
8. Build details string from all taxonomy entries

Never raises — returns `{"verdict": "unknown", "score": 0, "details": "..."}` on any failure.

### `tools/itop.py` — iTop CMDB Lookup

**Function: `lookup_asset(hostname_or_ip) -> dict`**

Uses iTop JSON-RPC API: `POST {ITOP_URL}/webservices/rest.php?version=1.3` with multipart form data (`auth_user`, `auth_pwd`, `json_data` as form fields).

Queries `SELECT Server WHERE (name = '{hostname_or_ip}' OR ip = '{hostname_or_ip}')` with output fields: id, name, status, business_criticality, location_name, contacts_list, services_list, description, org_name, network_zone.

Returns: `found`, `hostname`, `criticality`, `status`, `location`, `organization`, `contacts`, `services`, `description`, `network_zone`.

Returns `{"found": False, "error": "..."}` if iTop not configured, request fails, or no asset found.

### `tools/thehive.py` — TheHive Case Search

**3 functions:**

- **`search_open_cases(observables, host, user)`** — POST to `/api/v1/query` with `bool/should` clauses. Filters to `status IN ["Open", "InProgress"]`. Returns list of simplified case dicts (case_id, title, severity, status, tags, description, host, user, observables, created_at). Returns empty list on error.

- **`search_closed_cases(rule_uuid, observables)`** — Same query structure but filters to `status IN ["Resolved", "Closed"]`. Adds `size: 20`, `sort: [createdAt: desc]`. Returns list with additional `resolution` and `summary` fields.

- **`get_case_full(case_id)`** — GET `/api/v1/case/{case_id}`. Returns full case context: case_id, title, description, severity, status, tags, metrics, custom_fields, created_at, owner, summary. Returns None on error.

Auth: Bearer token in `Authorization` header.

### `tools/elasticsearch.py` — Elasticsearch Queries

**3 functions, all query Security Onion's Elasticsearch indices:**

- **`query_related_alerts(host, user, iocs, window_hours=24)`** — Queries `.ds-logs-detections.alerts-so-*`. Filters by timestamp range + multi_match on host, user, iocs. Returns summarized hits with timestamp, rule_name, rule_uuid, severity, src_ip, dst_ip, hostname, username, category.

- **`query_process_history(host, user, window_hours=24)`** — Queries `.ds-logs-endpoint.process-*`. Returns process details: timestamp, hostname, user, process_name, process_path, command_line, pid.

- **`query_connection_history(src_ip, dst_ip, window_hours=24)`** — Queries `.ds-logs-network.flow-*`. Filters by term match on src_ip/dst_ip. Returns flow details: timestamp, src_ip, dst_ip, src_port, dst_port, protocol, bytes, action, hostname.

All functions: max 50 results, sorted by timestamp descending. Auth via `ApiKey {ES_API_KEY}` header. Return empty list on error.

### `tools/sigma_rules.py` — Sigma Rule Lookup

**Function: `get_rule_source(rule_uuid) -> dict`**

Walks the `SIGMA_RULES_PATH` directory recursively, opens every `.yml`/`.yaml` file, parses with `yaml.safe_load`, and matches `data.get("id")` against the requested UUID.

On match, extracts: `title`, `description`, `id`, `level`, `status`, `falsepositives`, `tags`, `mitre_attack` (tags prefixed with "attack."), `references`, `author`, `detection`, `logsource`.

Returns `{"found": False, "error": "..."}` if directory not found or UUID not matched.

### `tools/qdrant.py` — Qdrant Vector Search

**3 functions:**

- **`retrieve_mitre(query_text, top_k=5)`** — Searches `mitre_attack` collection (or `triage_kb`). Returns: score, tactic, technique, technique_id, sub_technique, description.
- **`retrieve_playbooks(query_text, top_k=3)`** — Searches `playbooks` collection (or `triage_kb`). Returns: score, title, content, tags.
- **`retrieve_cve(query_text, top_k=3)`** — Searches `cve` collection (or `triage_kb`). Returns: score, cve_id, description, cvss_score, affected_software.

Uses lazy singleton `QdrantClient` instance. Calls `client.query_points()` with `models.Document(text=query_text, model=client.DEFAULT_EMBEDDING_MODEL)` for automatic embedding. Returns empty list on error.

### `tools/registry.py` — LangChain Tool Registry

Wraps each backend function with `@tool` decorator, providing:
- `cortex_analyze(observable_type, observable_value)` → wraps `tools.cortex.analyze_observable`
- `itop_asset_lookup(hostname)` → wraps `tools.itop.lookup_asset`
- `elasticsearch_query(index_type, host, user, iocs, window_hours)` → wraps all 3 ES functions with dispatch on `index_type`
- `thehive_search(query_type, observables, host, user, case_id)` → wraps all 3 TheHive functions
- `sigma_rule_lookup(rule_uuid)` → wraps `tools.sigma_rules.get_rule_source`
- `qdrant_retrieve(collection, query_text, top_k)` → wraps all 3 Qdrant functions

`TOOLS` list is imported by `nodes/investigate.py` and passed to `create_react_agent`.

---

## Prompts (System Prompts for Both Agents)

### `prompts/investigator.py` — Agent 1 System Prompt

**`BASE_PROMPT`** — Core instructions:
- Mission: senior SOC investigator, gather ALL evidence
- All tools are READ-ONLY (observe, don't act)
- Stop early if verdict is clear, mark unused budget
- Tool call discipline: call cheapest/fastest first, use findings to decide next call
- If tool fails with wrong parameter → fix and retry ONCE
- Output format: strict JSON (no markdown, no backticks)

**`PROFILE_BLOCKS`** — 5 investigation profiles + 1 generic fallback:

| Profile | Focus | Use | Avoid |
|---------|-------|-----|-------|
| `network_threat` | TI on IPs/domains, asset, connections | cortex, itop, elasticsearch(connections) | process/user queries |
| `endpoint_behavior` | Rule FP, process ancestry, hashes, user behavior | sigma_rules, elasticsearch(process), cortex(hashes), itop | network flows |
| `malicious_file` | Hash rep, Zeek origin, other hosts with same hash | cortex(hashes), elasticsearch(sessions), itop | process/user auth |
| `network_anomaly` | Rule FP, IP/domain TI, asset | sigma_rules, cortex, itop | — |
| `log_anomaly` | Log source, rule FP, user/entity history | sigma_rules, elasticsearch(user/entity), itop | — |
| `generic` (default) | All available evidence | All tools | — |

**`build_prompt(profile, mode)`** — Concatenates BASE_PROMPT + profile block + mode instruction ("NEW alert" or "MODE: MERGE").

**Output JSON schemas defined in prompt:**
- NEW: rule_context{}, asset_context{}, threat_intel[], temporal_context{}, historical_context{}, investigation_gaps[], investigation_trace[]
- MERGE: new_iocs[], new_hosts[], new_users[], new_kill_chain_stages[], changed_ti_verdicts[], additional_context{}, investigation_gaps[], investigation_trace[]

### `prompts/analyst.py` — Agent 2 System Prompt

**`BASE_PROMPT`** — Core instructions:
- Respond with ONLY valid JSON (no markdown, no backticks, no explanations)
- Zero tools — analyze evidence only
- Never see raw logs or raw API responses (prompt injection firewall)
- Every reasoning claim MUST cite a specific evidence field
- Quality bar: verdict only as good as cited evidence, "I don't know" (needs_review) is correct

**7-step reasoning process (for new alerts):**
1. Likelihood (unlikely | possible | likely | near_certain) — based on TI verdicts, rule FP, behavioral context, temporal clustering, historical cases
2. Impact if true (minor | moderate | severe | critical) — based on asset criticality, technique severity, scope, data sensitivity
3. MITRE mapping (array of {tactic, technique, sub_technique, confidence, basis}) — confidence capped by evidence quality
4. Verdict (true_positive | false_positive | needs_review)
5. Reasoning — every claim cites a field name
6. Recommended action (create_case | close_fp | needs_review)
7. Summary — 3-5 sentences, no jargon

**`MERGE_PROMPT`** — Single question: "Does this new evidence materially change the case?" Output: severity_change, new_mitre_stages[], scope_change, urgency, recommended_action (merge_and_retier | merge_quiet), reasoning.

**`NEW_SCHEMA`** — JSON schema dict (documentation, not enforced by library)
**`MERGE_SCHEMA`** — JSON schema dict for merge output
**`GBNF_GRAMMAR`** — llama.cpp-compatible GBNF grammar string for constrained JSON generation at inference server level

**`build_prompt(mode)`** — Returns BASE_PROMPT + MERGE_PROMPT (if merge mode)
**`output_schema(mode)`** — Returns NEW_SCHEMA or MERGE_SCHEMA

---

## Configuration

### `.env` — All Credentials (gitignored)

```ini
CORTEX_URL=http://172.20.24.221:9001
CORTEX_API_KEY=<key>
THEHIVE_URL=http://172.20.24.221:9000
THEHIVE_API_KEY=<key>
ITOP_URL=http://172.20.24.223/itop
ITOP_USER=admin
ITOP_KEY=<password>
ES_URL=https://172.20.24.58
ES_API_KEY=<base64-key>
LLM_BASE_URL=http://172.20.24.225/v1
LLM_MODEL=llama3.2:3b
QDRANT_URL=http://172.20.24.224:6333
SIGMA_RULES_PATH=/opt/so/rules/sigma
# Optional:
# REDIS_URL=redis://localhost:6379
# MAX_TOOL_CALLS_NEW=8
# MAX_TOOL_CALLS_MERGE=5
# DEDUP_WINDOW_SECONDS=300
```

### Qdrant State (as of last check)

| Collection | Points | Contents |
|-----------|--------|----------|
| `triage_kb` | 2,412 | MITRE ATT&CK techniques + CVE data + playbooks (combined collection) |

---

## Qdrant Ingestion Script (`scripts/ingest_qdrant.py`)

Standalone script to populate Qdrant vector collections. Uses `BAAI/bge-small-en` embedding model (384 dimensions, Cosine distance).

**Commands:**
- `python scripts/ingest_qdrant.py mitre` — Downloads MITRE ATT&CK STIX bundle from MITRE CTI GitHub, extracts tactics and attack-patterns, builds embeddings for ~850 techniques with payload: technique_id, technique, tactic, sub_technique, description, parent_technique.
- `python scripts/ingest_qdrant.py cve --max-cves=5000` — Fetches CVEs from NVD API 2.0 in batches of 200 with 0.6s delay (rate limiting). Extracts CVE ID, description, CVSS score, affected software. Up to 5000 CVEs.
- `python scripts/ingest_qdrant.py playbooks <dir>` — Walks directory for .md/.yaml/.yml files, parses YAML front matter for title and tags, chunks content up to 5000 chars.
- `python scripts/ingest_qdrant.py all --playbooks-dir=<dir>` — Runs all three.

Handles: collection creation/recreation, batch embedding (10 texts/batch), batch upsert (50 points/batch), stable point IDs via SHA-256 hash, NVD 429 rate limiting with exponential backoff.

---

## Tests (61 tests across 7 files)

`python -m pytest tests/ -v`

| Test File | Tests | What It Tests |
|-----------|-------|---------------|
| `test_schemas.py` | 11 | All Pydantic models: minimal/full construction, defaults, serialization, merge/dedup/new TriageResult paths, TypedDict mutability |
| `test_graph.py` | 5 | Route dedup→format_output, route new/merge→investigate, route when no correlation result, all 4 nodes registered |
| `test_correlate.py` | 13 | Tactic indexing (valid + unknown), tactics_from_techniques (valid + empty), kill-chain progression (true/false/no_match/unknown/full_range), correlate function (new/dedup/entity_match/story_match/no_host) |
| `test_format_output.py` | 9 | Severity table coverage (all 16 cells valid), dedup path (no verdict), new path (high/low/critical severity), merge quiet path (no severity change), merge retier path (severity upgrade), no_verdict fallback, trace passthrough |
| `test_analyze.py` | 10 | JSON extraction (simple/nested/markdown/text/surrounding/empty/no_braces/unclosed), evidence summarization (full/empty/none/dict) |
| `test_prompts.py` | 9 | Investigator (new/merge/generic/all 5 profiles), analyst (new/merge), output schemas (new/merge), profile blocks completeness |

---

## Dependencies (`requirements.txt`)

| Package | Purpose |
|---------|---------|
| `fastapi` | Web framework |
| `uvicorn` | ASGI server |
| `langgraph` | State machine / graph framework |
| `langchain` | LLM abstraction |
| `langchain-community` | Community integrations |
| `langchain-openai` | OpenAI-compatible LLM client |
| `pydantic` | Data validation / schemas |
| `requests` | HTTP client for tools |
| `python-dotenv` | .env file loading |
| `qdrant-client` | Qdrant vector DB client |
| `fastembed` | Local embedding inference |
| `redis` | Redis client for dedup |
| `pyyaml` | YAML parsing for Sigma rules |

---

## Data Flow Summary (End to End)

1. n8n receives Security Onion alert from Elasticsearch
2. n8n parses raw JSON into `CanonicalAlert`, creates TheHive alert, queries observable IDs
3. n8n sends `POST /triage` to agent-service with `CanonicalAlert` body
4. **Correlate**: Redis dedup check → if dup, return `deduplicated` immediately. Else check TheHive entity match → if match, set merge mode. Else check kill-chain story match → if match, set merge mode. Else set new mode.
5. **Investigate**: LLM ReAct agent selects tools based on investigation profile, gathers evidence (rule context, asset context, threat intel, temporal context, historical context), produces structured `EvidencePackage` (new) or `DeltaEvidence` (merge). Max 8 tool calls (new) or 5 (merge).
6. **Analyze**: LLM receives summarized evidence, reasons through likelihood/impact/MITRE/verdict, produces `TriageVerdict` (new) or `DeltaVerdict` (merge). No tools, no raw data.
7. **Format Output**: Map likelihood×impact to severity via lookup table. Build `TriageResult`. If merge mode, extract new severity from severity_change string.
8. n8n receives `TriageResult`, switches on `action`: create_case → promote alert to case, close_fp → close alert, needs_review → flag for analyst, merge_quiet → add to existing case, merge_and_retier → add + update severity + notify, deduplicated → log and stop.
