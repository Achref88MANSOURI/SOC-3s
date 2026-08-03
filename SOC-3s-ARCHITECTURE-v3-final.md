# SOC-3s Agent Service — Architecture v3 (Final)

**Supersedes:** All earlier v3 drafts. Kibana integration was evaluated, prototyped
at the infrastructure level, and reverted. This is the settled design.

---

## 1. What changed from v2, and what was tried and reverted

### Kept from v2
Same 3-agent design, same Gate 0, same TheHive/Cortex/iTop/Qdrant direct-REST
approach, same rejection of MCP for TheHive/Elasticsearch.

### Changed in v3

**Tool duplication eliminated.** Agent 1 and Agent 2 no longer share tools. Agent 1
owns open-case correlation and MITRE tag extraction. Agent 2 owns closed-case
history, telemetry, and enrichment. No tool appears in both agents' lists.

**`sigma_rule_lookup` renamed to `detection_rule_lookup`, extended to Suricata.**
Suricata rules carry MITRE metadata too — confirmed 24,264 of 48,333 active
signatures (50.2%) in this deployment's `/opt/so/rules/nids/suri/all.rules` have
`mitre_technique_id` fields. YARA has no native tagging — handled with a graceful
empty-return.

**`alert_builder.py` reads `event_data` directly, not regex over description text.**
A live SO Sigma alert (captured from the actual n8n webhook payload) confirmed the
full Sysmon event — process, parent process, hashes, user, host, command line — is
already embedded under `event_data.process`, `event_data.user`, `event_data.host` in
the raw alert. The current implementation's regex-over-description approach is
fragile and unnecessary when the structured fields are present. This is now a
required fix, not a nice-to-have.

**Cortex tool demoted to fallback-only in Agent 2.** n8n already triggers analyzers
on all observables; results are fetched via `get_full_alert_with_analysis()`. Agent 2
only calls Cortex directly for IOCs discovered during investigation that weren't on
the original alert.

### Tried and reverted: Kibana Security alert integration

A `query_kibana_alerts` tool and a parallel Kibana-alert ElastAlert trigger were
investigated in depth against the live deployment. Findings, kept here for the
record so this doesn't get re-litigated:

- Kibana Security alerts (`.alerts-security.alerts-default`, confirmed live,
  188,877 documents) are a genuinely separate detection engine from SO's own
  Suricata/Sigma/YARA — they do carry rich native MITRE ATT&CK mapping
  (`kibana.alert.rule.threat`) and embedded investigation guides
  (`kibana.alert.rule.note`) for most rule types.
- However: not every Kibana alert has `threat` populated — threshold/aggregation
  rule types (e.g. "Multiple Alerts in Different ATT&CK Tactics on a Single Host")
  return an empty `[]`. Any consumer must be null-safe.
- Every Kibana alert observed in this deployment fired on endpoint telemetry
  (Sysmon, Elastic Defend API/file/process events) — never on network-flow data.
  A Suricata-sourced alert would almost always find nothing in Kibana, making a
  blanket enrichment call wasteful.
- No active threat-intelligence indicator-match feed is configured — Kibana
  provides MITRE *rule metadata*, not live IOC reputation. Cortex remains the only
  threat-intel source in this architecture.
- **Decision: reverted.** The team chose to keep Security Onion's own alerts
  (`.ds-logs-detections.alerts-so-*`) as the sole trigger into n8n, and Cortex as
  the sole threat-intel enrichment source. Kibana Security alerts are not queried,
  not used for triage enrichment, and not part of this pipeline. If revisited later,
  the null-safety and endpoint-only-relevance findings above still apply.

---

## 2. Pipeline Overview

```
Security Onion (Suricata / Sigma-ElastAlert2 / YARA-Strelka)
        │
        │  ONLY trigger source — .ds-logs-detections.alerts-so-*
        │  webhook
        ▼
n8n Workflow:
  1. Alert Builder — extract IOCs, build TheHive alert body
  2. Create Alert in TheHive
  3. Get Observable IDs
  4. Switch on dataType → Cortex analyzers (stays — n8n triggers, agent reads results)
  5. Query iTop for asset context
  6. POST /triage → agent-service (slim AlertWebhookPayload)
  7. Switch on TriageResult.action → case management
        │
        ▼
agent-service:
  main.py → fetch full alert from TheHive (with Cortex reports)
          → build_canonical_alert()   [reads event_data directly — see §5]
          → graph.invoke()

  GATE 0:  Redis dedup (pure Python)
  AGENT 1: Perceive — normalize, MITRE map, correlate (LLM + 3 tools)
  AGENT 2: Investigate — gather evidence (LLM ReAct + 5 tools)
  AGENT 3: Analyze — verdict (single LLM call, 0 tools)
  FORMAT:  Severity lookup → TriageResult
        │
        ▼
  TriageResult → n8n → TheHive case actions (human-approved)
```

---

## 3. Input Contract

Unchanged. `POST /triage` receives `AlertWebhookPayload`:

```json
{
  "thehive_alert_id": "~1156182192",
  "raw_alert": { "type": "sigma", "source": "security-onion", ... },
  "asset_context": { "business_criticity": "high", ... }
}
```

---

## 4. Gate 0 — Redis Dedup

Unchanged. Pure Python. `sha256(rule.uuid + host + user + ips)`. Redis optional.

---

## 5. `alert_builder.py` — Read `event_data` Directly

**This is the confirmed fix, based on a real captured webhook payload.**

A Sigma alert's `raw_alert` contains, under `event_data`, the full originating
Sysmon/winlog event:

```
event_data.process.command_line       full command line
event_data.process.name                 process name
event_data.process.executable           full path
event_data.process.hash.sha256/md5      file hashes
event_data.process.pe.imphash           import hash
event_data.process.parent.name          parent process
event_data.process.parent.command_line  parent command line
event_data.process.parent.pid           parent PID
event_data.process.working_directory
event_data.user.name / user.id
event_data.host.hostname / host.ip / host.os
event_data.agent.id                     Elastic Agent ID
```

**Fix required:** `build_canonical_alert()` must read these fields directly when
`event_data` is present, rather than relying solely on regex extraction from the
`description` string. The regex approach stays as a fallback for alert shapes that
lack `event_data` (e.g. some Suricata/YARA alert bodies), but for Sigma alerts —
which carry the full Sysmon event — structured extraction must be tried first.

Known defensive requirement carried over from earlier analysis: observable
`dataType` values from n8n's IOC extraction are not always trustworthy (a URL was
previously seen mistyped as `dataType: "domain"`) — sanity-check by value shape,
not by the stated type.

---

## 6. Agent 1 — Perceive and Normalize

**File:** `nodes/perceive.py`
**Type:** LLM ReAct loop, max 4 tool calls

### Tools — Agent 1 only

| Tool | What it does |
|------|-------------|
| `detection_rule_lookup` | Reads rule source by UUID. Sigma → YAML tags. Suricata → `.rules` metadata (see §7 for the exact matching logic — this was corrected mid-project). YARA → graceful empty return. |
| `thehive_open_cases` | Open/in-progress case search. Agent 1 reasons about match strength (rare hash vs common domain, temporal proximity). |
| `qdrant_retrieve_mitre` | MITRE technique candidates when rule tags are absent; also used for kill-chain progression reasoning. |

No `thehive_search_closed`, no `qdrant_retrieve` (CVE/playbooks), no
`elasticsearch_query`, no `cortex_analyze`, no `itop_asset_lookup` — those are
Agent 2's domain.

### Sub-tasks

1. Read detection rule source (`detection_rule_lookup`) — highest-confidence MITRE
   source when available.
2. Infer MITRE techniques via Qdrant when tags are absent or insufficient.
3. Search open cases; reason about correlation strength, not string equality.
4. Kill-chain progression check on any merge candidate.
5. Output `CorrelationResult(action, mode, reason, confidence)`.

### Fallback

Parse failure → same deterministic entity-match logic the old `correlate.py` used.

---

## 7. `detection_rule_lookup` — Corrected Suricata Matching Logic

**Critical correction made mid-project, recorded here to prevent regression:**
the Suricata `sid` field is **not** a MITRE ATT&CK technique ID. It is Emerging
Threats' own sequential rule identifier (e.g. `sid:2522726`). It is used purely as
the **lookup key** to find the correct line in the rules file — the actual MITRE
data, when present, lives in that same rule's `metadata:` block as separate
key-value pairs.

**Confirmed real rule format** (pulled directly from this deployment):

```
alert tcp ... (msg:"ET ACTIVEX ..."; ...; sid:2010665; rev:7;
metadata:affected_product ..., mitre_tactic_id TA0001,
mitre_tactic_name Initial_Access, mitre_technique_id T1190,
mitre_technique_name Exploit_Public_Facing_Application;)
```

**Confirmed a rule can legitimately have zero MITRE fields:**

```
alert tcp [...] any -> $HOME_NET any (msg:"ET TOR Known Tor Relay/Router...";
...; sid:2522726; rev:6172; metadata:affected_product Any,
attack_target Any, deployment Perimeter, tag TOR,
signature_severity Informational, created_at 2008_12_01, updated_at 2026_02_19;)
```

**Confirmed coverage in this deployment:**
- Total active rules: 48,333
- Rules with `mitre_technique_id`: 24,264 (50.2%)

### Parser logic

1. Confirmed location: `/opt/so/rules/nids/suri/all.rules` (single combined file,
   not a per-rule directory like Sigma).
2. Scan lines for `sid:{rule_uuid};` — skip lines starting with `#` (disabled rules).
3. On match, extract from that line:
   - `msg:"..."` → title
   - `metadata:` block → parse comma-separated key-value pairs for
     `mitre_technique_id`, `mitre_technique_name`, `mitre_tactic_id`,
     `mitre_tactic_name` (may be absent entirely — that's a valid, common case)
4. Return `{"found": true, "source_engine": "suricata", "mitre_attack": [...],
   "mitre_tactics": [...], ...}` — empty lists when metadata lacks MITRE fields,
   not an error.

---

## 7a. FP History Tracking — Closing the Loop on Closed Alerts

**Problem this solves:** today, once Agent 3 says `false_positive`, the reasoning
evaporates. Next time the same rule fires on the same host, Agent 1 and Agent 2
re-investigate from zero, and Agent 3 spends the same LLM budget reaching the same
conclusion. Nothing persists a rule's or a host's historical noise pattern anywhere
the system can check cheaply before doing full investigation.

**Research grounding:** AACT (Turcotte, Labrèche, Paquette — arXiv:2505.09843,
2025) found that the single strongest predictor of a future triage decision is how
analysts have triaged similar alerts in the recent past — and critically, that this
must be captured as **two separate time windows**, not one running total:
- **Short-term** (hours/a day): captures active incident context — is this entity
  behaving noisily *right now*.
- **Long-term** (30+ days): captures organizational baseline — is this rule or host
  *chronically* noisy (e.g., a scanner, a discovery rule that fires on routine admin
  activity).
A flat all-time counter erases exactly this distinction, which is the actual signal.

**Design decision:** local SQLite counter (fast, always checked) + conditional
TheHive query (only when the counter indicates it's worth pulling the detailed past
reasoning). Not Redis (ruled out — not compatible with this deployment). Not Qdrant
(wrong tool — this is exact-match counting, not semantic similarity).

### Schema

```sql
CREATE TABLE fp_events (
    id INTEGER PRIMARY KEY,
    rule_uuid TEXT NOT NULL,
    host TEXT NOT NULL,
    is_fp BOOLEAN NOT NULL,
    triage_timestamp TEXT NOT NULL,
    verdict_confidence TEXT   -- Agent 3's confidence at the time, for future weighting
);
CREATE INDEX idx_rule_host_time ON fp_events(rule_uuid, host, triage_timestamp);
```

One row written per completed triage, at the point `format_output` already knows
the verdict — not gated on `case_action.py`'s human-approval step, since that may
never run. This reflects the agent's own judgment history.

### Query — `get_fp_signal(rule_uuid, host)`

```python
def get_fp_signal(rule_uuid: str, host: str) -> dict:
    short_term = query(rule_uuid, host, window="24h")
    long_term  = query(rule_uuid, host, window="30d")
    return {
        "short_term_fp_rate": short_term.fp_count / max(short_term.total, 1),
        "long_term_fp_rate":  long_term.fp_count / max(long_term.total, 1),
        "short_term_total": short_term.total,
        "long_term_total": long_term.total,
    }
```

### Where this fits — Agent 1, first and cheapest check

```
1. get_fp_signal(rule.uuid, host.hostname)     -> instant, local, always run
2. IF long_term_fp_rate > 0.5 AND long_term_total >= 5 (enough samples to trust):
       thehive_fp_history(rule_uuid, host, limit=3)  -> TheHive query, only now,
                                                          for the actual reasoning
                                                          text from past closures
3. detection_rule_lookup(...)   -> as before
4. qdrant_retrieve_mitre(...)   -> as before
5. thehive_open_cases(...)      -> as before
```

`thehive_fp_history` searches TheHive alerts with `status: "Ignored"` matching
`rule.uuid`/host, returning each past alert's ID, title, and the comment
`case_action.py` wrote when it closed it. This is conditional and rare by design —
most alerts never touch TheHive for this, keeping the added latency near zero for
the common case.

### Guardrail — informs, never auto-decides

A high FP rate is a strong prior, not a verdict. Agent 3 reasons over it alongside
asset criticality, process context, and the rest of the evidence — the same noisy
discovery rule firing on an admin's routine `whoami` is different from it firing
during an active incident on a critical server. The `verdict_confidence` field
exists so a future refinement can down-weight past verdicts that were themselves
low-confidence, rather than treating every historical closure as equally trustworthy.
This mirrors CORTEX's explicit caution that purely statistical FP models are brittle
to novel patterns and need continuously curated history, not blind trust.

---

## 8. Agent 2 — Investigate

**File:** `nodes/investigate.py`
**Type:** LLM ReAct loop, max 8 tool calls (new) / 5 (merge)

### Tools — Agent 2 only

| Tool | What it does |
|------|-------------|
| `thehive_search_closed` | Resolved/closed case history — "has this rule fired before, what happened?" |
| `elasticsearch_query` | SO telemetry: related alerts (`.ds-logs-detections.alerts-so-*`), process history, connection flows. |
| `itop_asset_lookup` | Business criticality, owner, network zone. |
| `qdrant_retrieve` | CVE and playbook context only — not MITRE (that's Agent 1's domain). |
| `cortex_analyze` | Fallback only — newly discovered IOCs not on the original alert. Check `canonical_alert.cortex_results` first. |

No `thehive_open_cases`, no `detection_rule_lookup`, no `qdrant_retrieve_mitre`, no
Kibana tool of any kind.

### Tool call discipline

1. Check pre-loaded Cortex results first — do not re-analyze observables that
   already have a report.
2. Cheapest first: `itop_asset_lookup` → `elasticsearch_query` →
   `thehive_search_closed` → `qdrant_retrieve` → `cortex_analyze` (rare).
3. Skip common infrastructure for Cortex (github.com, 8.8.8.8, etc.) — log as
   `investigation_gaps`.
4. Stop early once verdict is clear.

### Investigation profiles

| Profile | Priority tools |
|---------|----------------|
| `network_threat` (Suricata) | `elasticsearch_query` (connections), `itop_asset_lookup` |
| `endpoint_behavior` (Sigma + process) | `elasticsearch_query` (process history), `itop_asset_lookup`, `thehive_search_closed` |
| `malicious_file` (YARA) | `cortex_analyze` (only if no existing report), `elasticsearch_query` (Zeek/session origin) |
| `network_anomaly` (Sigma + network) | `elasticsearch_query`, `itop_asset_lookup` |
| `log_anomaly` | `elasticsearch_query` (user/entity history), `itop_asset_lookup` |

### Structured output

Unchanged from v2 Phase 5 — `EvidencePackage`/`DeltaEvidence` JSON schema enforced,
fallback-from-trace on parse failure.

---

## 9. Agent 3 — Analyze and Decide

Unchanged. Single LLM call, zero tools, two-pass MITRE validation
(Agent 1 infers fast, Agent 3 validates against evidence — tested with a
no-blind-passthrough assertion).

---

## 10. Format Output / Case Action

Unchanged from v2. Severity lookup table. `case_action.py` stub, `"Ignored"` for FP
status (confirmed against live TheHive 5.6.1 — `"FP"` does not exist).

---

## 11. Tool Inventory — Final

```
tools/detection_rules.py    (renamed from sigma_rules.py)
  get_rule_source(rule_uuid, source_engine=None) -> dict
  dispatches: Sigma YAML -> Suricata .rules metadata -> YARA graceful return

tools/thehive.py
  get_full_alert_with_analysis(alert_id)     # pre-agent, main.py
  search_open_cases(...)                      # Agent 1 only
  search_closed_cases(...)                    # Agent 2 only
  get_case_full(case_id)                      # Agent 1, on merge
  promote_alert_to_case / update_case /
  add_case_comment / update_alert_status /
  add_alert_comment / merge_alert_into_case   # case_action.py only, post-approval

tools/elasticsearch.py
  query_related_alerts / query_process_history /
  query_connection_history                    # Agent 2 only
  # query_kibana_alerts — NOT BUILT, reverted, do not add

tools/cortex.py
  analyze_observable(...)                     # Agent 2, fallback only

tools/itop.py
  lookup_asset(...)                           # Agent 2 only

tools/qdrant.py
  retrieve_mitre(...)                         # Agent 1 only
  retrieve_playbooks(...) / retrieve_cve(...)  # Agent 2 only

tools/registry.py
  PERCEPTION_TOOLS = [detection_rule_lookup, thehive_open_cases, qdrant_retrieve_mitre,
                       get_fp_signal, thehive_fp_history]
  INVESTIGATION_TOOLS = [thehive_search_closed, elasticsearch_query,
                          itop_asset_lookup, qdrant_retrieve, cortex_analyze]

tools/fp_tracking.py         (NEW)
  get_fp_signal(rule_uuid, host) -> dict     # SQLite, always run, Agent 1
  thehive_fp_history(rule_uuid, host, limit) # TheHive, conditional, Agent 1
  record_triage_outcome(rule_uuid, host, is_fp, confidence)  # called from
                                                               # format_output.py
                                                               # on every triage
```

---

## 12. Technology Stack — Final

| Component | Technology |
|-----------|-----------|
| LLM | `qwen3:30b-a3b` via Ollama (CPU, 16 cores, 64GB RAM) |
| Agent framework | LangGraph + LangChain |
| Vector DB | Qdrant, `BAAI/bge-m3` (1024-dim), `sentence-transformers`, `triage_kb` collection |
| TheHive access | Raw `requests`, verified against 5.6.1 |
| Elasticsearch access | Raw `requests`/`elasticsearch-py`, direct API, not MCP |
| Cortex access | Raw `requests`, fallback-only in Agent 2 |
| iTop access | Raw `requests`, JSON-RPC |
| Case writes | Direct REST, post-approval gate, `"Ignored"` for FP |
| Trigger source | SO alerts only (`.ds-logs-detections.alerts-so-*`) — Kibana reverted |

### Rejected (with rationale)

| Decision | Why rejected |
|----------|--------------|
| Elasticsearch MCP | Official server deprecated; requires ES 9.2.0+ (SO runs 8.x); token overhead for single consumer |
| TheHive MCP | BETA, prompt-injection risk, case corpus is machine-structured — REST outperforms NL search |
| Cortex MCP (`cortex-mcp`) | stdio transport can't cross the agent-service/Cortex VM boundary |
| Kibana Security alert integration | Endpoint-only relevance, no threat-intel value beyond MITRE rule metadata, null-safety complexity, team decided SO alerts alone are sufficient |
| Qdrant → Elasticsearch migration | Production ES cluster risk; Qdrant already deployed and working |

---

## 13. Build Order — v3 Final Delta

```
PHASE A — alert_builder.py event_data fix
  Read event_data.process/user/host directly for Sigma alerts
  Keep regex-over-description as fallback for alerts lacking event_data
  Observable dataType sanity check preserved
  Tests: real captured payload as fixture, confirm structured extraction
         takes precedence over regex when event_data present

PHASE B — Rename and extend detection_rules.py
  sigma_rules.py -> detection_rules.py
  Add Suricata .rules parser: match sid:{uuid}; skip commented lines;
    extract mitre_technique_id/name, mitre_tactic_id/name from metadata
    block; MISSING metadata is a valid, common, non-error case
  Add YARA graceful return
  SURICATA_RULES_PATH default: /opt/so/rules/nids/suri/all.rules
  Tests: Suricata rule with MITRE metadata, Suricata rule without it,
         commented rule skipped, YARA graceful return, unknown UUID

PHASE C — Split tool lists in registry.py
  PERCEPTION_TOOLS: detection_rule_lookup, thehive_open_cases,
                     qdrant_retrieve_mitre
  INVESTIGATION_TOOLS: thehive_search_closed, elasticsearch_query,
                        itop_asset_lookup, qdrant_retrieve, cortex_analyze
  Split thehive_search -> thehive_open_cases / thehive_search_closed
  Split qdrant_retrieve -> qdrant_retrieve_mitre / qdrant_retrieve (cve+playbooks)
  Assert zero tool overlap between the two lists
  Update nodes/perceive.py and nodes/investigate.py imports

PHASE D — Update prompts
  prompts/perceiver.py: document detection_rule_lookup (3 engines)
  prompts/investigator.py: remove sigma_rule_lookup/thehive_open_cases/
    qdrant_retrieve_mitre references; add "check cortex_results first"
    instruction; no Kibana references anywhere

PHASE E — Cleanup: delete outdated files
  Delete all superseded prompt/architecture drafts
  Keep: ARCHITECTURE.md (this doc), CHANGES.md, N8N-INTEGRATION.md

PHASE F — End-to-end validation
  pytest tests/ -v
  Verify zero references to "kibana" anywhere in tools/, nodes/, prompts/
  Update CHANGES.md

PHASE G — FP history tracking (see §7a for full design)
  New tools/fp_tracking.py: SQLite schema (fp_events table), get_fp_signal()
    (short-term 24h + long-term 30d windows, per AACT), thehive_fp_history()
    (conditional, only when long_term_fp_rate > 0.5 and long_term_total >= 5),
    record_triage_outcome()
  Wire record_triage_outcome() into nodes/format_output.py — called on every
    completed triage, not gated on case_action.py's approval step
  Add get_fp_signal + thehive_fp_history to PERCEPTION_TOOLS (Agent 1 checks
    this FIRST, before detection_rule_lookup)
  Update prompts/perceiver.py: document the two-tier FP signal, and the
    explicit instruction that a high FP rate informs confidence, never
    auto-decides the verdict
  Tests: SQLite schema creation, short-term vs long-term window correctness,
    conditional TheHive query only fires above threshold, record writes on
    both TP and FP outcomes, graceful behavior when fp_events.db doesn't
    exist yet (first run)
```