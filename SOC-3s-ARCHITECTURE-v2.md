# SOC-3s Agent Service — Full Architecture v2
## Context document for Claude Code

**Document purpose:** Complete technical specification of the agent-service component
of the SOC-3s pipeline. Use this as the primary reference when reading, modifying, or
extending the codebase. Every architectural decision recorded here was made
deliberately — do not deviate from it without understanding the reasoning first.

**Status:** v2 — supersedes all earlier architecture notes in the repo.
**Last updated:** August 2026

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Full Pipeline — End to End](#2-full-pipeline--end-to-end)
3. [n8n Workflow — What It Does and What It Sends](#3-n8n-workflow--what-it-does-and-what-it-sends)
4. [Agent Service — Overview](#4-agent-service--overview)
5. [Gate 0 — Redis Dedup](#5-gate-0--redis-dedup)
6. [Agent 1 — Perceive and Normalize](#6-agent-1--perceive-and-normalize)
7. [Agent 2 — Investigate](#7-agent-2--investigate)
8. [Agent 3 — Analyze and Decide](#8-agent-3--analyze-and-decide)
9. [Format Output Node](#9-format-output-node)
10. [Case Action Step](#10-case-action-step)
11. [Tool Inventory](#11-tool-inventory)
12. [Schemas — All Pydantic Models](#12-schemas--all-pydantic-models)
13. [LangGraph State Machine](#13-langgraph-state-machine)
14. [Technology Stack — Final Decisions](#14-technology-stack--final-decisions)
15. [File Tree](#15-file-tree)
16. [Environment Configuration](#16-environment-configuration)
17. [Key Architectural Decisions and Rationale](#17-key-architectural-decisions-and-rationale)
18. [Implementation Bugs to Fix First](#18-implementation-bugs-to-fix-first)
19. [Build Order](#19-build-order)

---

## 1. Project Overview

SOC-3s is an open-source AI-assisted Security Operations Center pipeline built on top
of Security Onion, n8n, TheHive, Cortex, iTop, and a locally-hosted LLM. Its purpose
is to automate alert triage — reducing analyst workload, eliminating false positive
noise, and surfacing real incidents with full context — while keeping all response
actions under human analyst approval.

The `agent-service` is the AI reasoning core of this pipeline. It receives a security
alert from n8n, runs it through a 3-agent LangGraph state machine, and returns a
structured triage verdict that n8n uses to drive case management actions in TheHive.

### Core problems this architecture solves

- **Alert overload:** Security Onion generates alerts from three engines (Suricata,
  Sigma via ElastAlert2, YARA via Strelka) with different schemas and no unified
  triage. The agent normalizes, enriches, correlates, and scores every alert
  automatically.
- **Missing MITRE tags:** Sigma rules have `attack.txxxx` tags in their YAML source,
  but ElastAlert2 does not forward them into the generated alert document. The agent
  infers MITRE techniques from rule context and behavioral evidence.
- **Inconsistent case correlation:** Static string-matching on shared observables
  produces false positives (two alerts share `github.com`, unrelated threats) and
  false negatives (same threat actor, rotated infrastructure). The agent reasons about
  match strength.
- **Blanket Cortex analyzer triggering:** n8n's Switch node routes every observable
  to Cortex regardless of value, wasting quota on `github.com` and adding latency.
  Agent 2 selectively invokes analyzers based on observable priority.

---

## 2. Full Pipeline — End to End

```
┌──────────────────────────────────────────────────────────────────┐
│  DETECTION LAYER — Security Onion (distributed)                  │
│                                                                   │
│  Suricata (NIDS)     → network signature alerts                  │
│  Sigma/ElastAlert2   → behavioral/log alerts                     │
│  YARA/Strelka        → file hash / malware alerts                │
│                                                                   │
│  All three engines write to:                                      │
│  .ds-logs-detections.alerts-so-* (Elasticsearch)                 │
│  This is the unified alert stream.                                │
└────────────────────────────┬─────────────────────────────────────┘
                             │  webhook trigger (SO → n8n)
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  ORCHESTRATION LAYER — n8n workflow                               │
│                                                                   │
│  1. Webhook node receives raw Security Onion alert JSON           │
│  2. Alert Builder (Python Code node):                             │
│     - Extracts IOCs (IPs, domains, URLs, hashes)                  │
│     - Detects source engine (Suricata / Sigma / YARA)            │
│     - Resolves rule name, UUID, severity                         │
│     - Builds TheHive 5 alert body + observables array            │
│  3. HTTP POST → TheHive: creates alert with observables           │
│  4. HTTP GET → TheHive: fetches observable IDs                   │
│  5. HTTP GET → iTop: fetches asset context by hostname           │
│     (criticality, organization, status, asset_number)            │
│  6. HTTP POST → agent-service /triage                            │
│     body: AlertWebhookPayload (slim — see §3)                    │
│     waits synchronously for TriageResult                         │
│  7. Switch on triage_result.action:                              │
│     create_case    → promote alert to case in TheHive            │
│     close_fp       → update alert status to Ignored             │
│     merge_quiet    → add alert to existing case                  │
│     merge_and_retier → merge + update severity + notify SOC     │
│     needs_review   → flag alert for analyst                      │
│     deduplicated   → log only, stop                              │
└────────────────────────────┬─────────────────────────────────────┘
                             │  POST /triage (AlertWebhookPayload)
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  AGENT SERVICE — FastAPI + LangGraph                              │
│                                                                   │
│  main.py receives AlertWebhookPayload                            │
│  Calls thehive.get_full_alert_with_analysis(thehive_alert_id)    │
│  Builds CanonicalAlert from TheHive data + raw_alert + asset ctx │
│  Invokes LangGraph graph                                         │
│                                                                   │
│  GATE 0 ─── Redis fingerprint dedup (pure Python)                │
│    hit  → return action=deduplicated immediately                  │
│    miss → continue to Agent 1                                    │
│                                                                   │
│  AGENT 1 ── Perceive & Normalize (LLM + tools)                   │
│    - Normalize variant metadata into CanonicalAlert              │
│    - Infer MITRE ATT&CK mapping from context                     │
│    - Semantic case correlation via TheHive REST                  │
│    - Kill-chain progression via Qdrant MITRE RAG                 │
│    - Output: CanonicalAlert + mitre_mapping[] + CorrelationResult│
│                                                                   │
│  AGENT 2 ── Investigate (LLM ReAct + tools)                      │
│    mode=new:   full investigation, max 8 tool calls              │
│    mode=merge: delta only, max 5 tool calls                      │
│    - Selective Cortex analysis via direct REST (cortex-mcp reverted) │
│    - Historical alerts via Elasticsearch direct                  │
│    - Asset context via iTop direct                               │
│    - Past cases via TheHive REST                                 │
│    - MITRE/CVE/playbook RAG via Qdrant                          │
│    - Output: EvidencePackage or DeltaEvidence (structured JSON)  │
│                                                                   │
│  AGENT 3 ── Analyze & Decide (single LLM call, NO tools)         │
│    - Receives summarized evidence only (never raw data)          │
│    - Validates/refines Agent 1 MITRE mapping                    │
│    - Produces verdict: TP / FP / needs_review                   │
│    - Output: TriageVerdict or DeltaVerdict                       │
│                                                                   │
│  FORMAT OUTPUT ── Pure Python                                     │
│    - Severity = lookup[likelihood][impact_if_true]               │
│    - Builds TriageResult → returns to n8n                        │
└────────────────────────────┬─────────────────────────────────────┘
                             │  TriageResult JSON
                             ▼
                    n8n → case actions (step 7)
                             │
                             ▼  (post human-approval)
┌──────────────────────────────────────────────────────────────────┐
│  CASE ACTION STEP — TheHive REST (thehive4py)                     │
│  Gated behind explicit analyst approval (approved: bool)         │
│  promote / merge / comment via TheHive 5 API                     │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. n8n Workflow — What It Does and What It Sends

### What n8n does (simplified after v2 changes)

The v2 change simplifies n8n significantly. The old Switch → per-type Cortex analyzer
nodes are **removed**. Cortex analysis is now driven by Agent 2 selectively.

n8n's job is now:
1. Receive raw Security Onion webhook
2. Build TheHive alert body (Alert Builder Python node)
3. Create alert in TheHive (POST /api/v1/alert)
4. Fetch observable IDs (GET TheHive)
5. Fetch asset context from iTop
6. POST slim payload to agent-service
7. Handle TriageResult action routing

### The slim payload n8n sends to agent-service

```json
{
  "thehive_alert_id": "~1156182192",
  "raw_alert": {
    "type": "sigma",
    "source": "security-onion",
    "sourceRef": "6qS9fp8BiUkBvoTNPeON",
    "title": "[HIGH] Suspicious Invoke-WebRequest Execution - win-kvkmd51ggkq",
    "description": "Detection engine: sigma\nRule: Suspicious Invoke-WebRequest Execution (5e3cc4d8-3e68-43db-8656-eaaeefdec9cc)\nHost: win-kvkmd51ggkq (172.20.24.99)\nAgent ID: 1a52ee32-ef93-4f5a-b876-65bd1b7c795a\nCommand line: ...",
    "severity": 3,
    "tlp": 2,
    "pap": 2,
    "date": 1784710559000,
    "tags": [
      "172.20.24.99",
      "agent-id:1a52ee32-ef93-4f5a-b876-65bd1b7c795a",
      "engine:sigma",
      "rule:Suspicious Invoke-WebRequest Execution",
      "security-onion",
      "win-kvkmd51ggkq"
    ],
    "observables": [
      {"dataType": "domain", "data": "github.com", "ioc": true},
      {"dataType": "url", "data": "https://github.com/audibleblink/xordump/releases/download/v0.0.1/xordump.exe", "ioc": true},
      {"dataType": "hash", "data": "1c84c8632c5269f24876ed9f49fa810b49f77e1e92e8918fc164c34b020f9a94", "ioc": true, "tags": ["sha256"]},
      {"dataType": "hash", "data": "bf7a6e7a62c3f5b2e8e069438ac1dd3d", "ioc": false, "tags": ["imphash"]}
    ]
  },
  "asset_context": {
    "organization_name": "TrustShield",
    "status": "production",
    "business_criticity": "high",
    "asset_number": "SRV-0042"
  }
}
```

### Known issue in n8n IOC extraction — handle defensively

The Alert Builder node has a known mis-classification bug: URLs are sometimes stored
with `dataType: "domain"` (observed in real captured data from this project). Agent 1
must sanity-check observable values against their stated dataType and correct them.
A value starting with `http://` or `https://` is always a URL regardless of what
`dataType` says.

---

## 4. Agent Service — Overview

### Entry point and flow

```
POST /triage → AlertWebhookPayload
    │
    ├── thehive.get_full_alert_with_analysis(thehive_alert_id)
    │   Returns: alert metadata + tags + observables + Cortex reports
    │   (uses TheHive Query API with extraData=["reports"])
    │
    ├── alert_builder.build_canonical_alert(raw_alert, hive_alert, asset_context)
    │   Returns: CanonicalAlert
    │
    └── graph.invoke(initial_state)
        Returns: TriageResult
```

### LangGraph graph shape

```
CanonicalAlert
    │
    ▼
[GATE 0: Redis dedup] ── hit ──► [FORMAT_OUTPUT] ──► TriageResult(deduplicated)
    │
  miss
    │
    ▼
[AGENT 1: perceive] ──► CanonicalAlert + mitre_mapping[] + CorrelationResult
    │
    ├── action=deduplicated ──► [FORMAT_OUTPUT]
    │
    ├── action=new ──► [AGENT 2: investigate] (mode=new, max 8 calls)
    │
    └── action=merge ──► [AGENT 2: investigate] (mode=merge, max 5 calls)
                              │
                              ▼
                    [AGENT 3: analyze] (single LLM call, no tools)
                              │
                              ▼
                    [FORMAT_OUTPUT] ──► TriageResult
```

---

## 5. Gate 0 — Redis Dedup

**Type:** Pure Python, no LLM.
**Location:** `nodes/perceive.py` (runs before Agent 1 as a synchronous check)

### Purpose
Exact-repeat filter. If the same alert fired within the dedup window (default 5
minutes), skip the entire graph and return `deduplicated` immediately. Prevents LLM
token waste on burst duplicates.

### Fingerprint construction
```python
key = sha256(
    rule.uuid +
    host.hostname +
    user.name +
    ":" .join(sorted(observables.external_ips[:3]))
)
redis_key = f"triage:fingerprint:{key}"
```

### Behavior
- If Redis key exists within TTL → return `CorrelationResult(action="deduplicated")`
- If key does not exist → `SETEX key TTL alert_id`, continue to Agent 1
- If `REDIS_URL` is not configured → skip check entirely, never report a duplicate

### Configuration
```
REDIS_URL=redis://localhost:6379       # optional
DEDUP_WINDOW_SECONDS=300               # default 300 (5 min)
```

---

## 6. Agent 1 — Perceive and Normalize

**Type:** LLM agent (ReAct loop or structured single call — see implementation note)
**Location:** `nodes/perceive.py`
**Replaces:** `nodes/correlate.py` from v1

### Why this node exists (the core insight)

Security Onion's three detection engines produce fundamentally different alert
structures even after ECS normalization:

| Engine | Typical fields | Missing fields |
|--------|---------------|----------------|
| Suricata | src_ip, dst_ip, proto, alert.signature | process.*, user.* |
| Sigma/ElastAlert2 | process.command_line, user.name, host.name | network IPs (sometimes) |
| YARA/Strelka | file.hash.*, matched strings | process.*, user.*, network |

Additionally, Sigma rules carry `attack.txxxx` tags in their YAML source, but
ElastAlert2 does NOT forward them into the generated alert document. Static parsers
cannot reliably handle this variance. An LLM can.

### Six sub-tasks (in order)

**Sub-task 1 — Pre-LLM: Fetch full alert from TheHive (deterministic)**

Before the LLM runs, `main.py` calls `thehive.get_full_alert_with_analysis()` to
fetch the alert including observables and Cortex analyzer reports via TheHive's
`extraData` mechanism. This is a structured, deterministic REST call — no LLM needed.

The result is passed into Agent 1's context alongside `raw_alert` and `asset_context`.

**Sub-task 2 — Normalize variant metadata (LLM)**

The LLM reads:
- `raw_alert` (n8n Alert Builder output — has engine type, rule name, UUID, tags)
- TheHive fetch result (observables with Cortex reports, TLP/PAP, alert status)
- `asset_context` (iTop: criticality, org, status)

And produces a structured `CanonicalAlert` covering: rule context, host, user, network,
process, file, observables (correctly typed), Cortex results per observable.

**Observable dataType sanity check is mandatory:** a value starting with `http://` or
`https://` is always a URL. A value with dots but no scheme and a valid TLD is a
domain. The LLM must correct misclassifications from the Alert Builder.

**Sub-task 3 — MITRE ATT&CK mapping (LLM + Qdrant)**

Using the rule name, description, command lines, network behavior, and file operations,
the LLM infers MITRE techniques even when no `attack.txxxx` tag exists.

Process:
1. Call `sigma_rule_lookup(rule.uuid)` first — if the rule source has tags, treat them
   as high-confidence primary mappings
2. If no tags, call `qdrant_retrieve("mitre", query_text)` for technique candidates
3. LLM reasons over candidates and produces `mitre_mapping[]` with confidence + basis

Each mapping entry:
```json
{
  "tactic": "execution",
  "technique": "T1059.001",
  "sub_technique": null,
  "confidence": "high",
  "basis": "PowerShell Invoke-WebRequest in command line"
}
```

Confidence levels: `high` (rule tag present), `medium` (strong contextual evidence),
`low` (inferred from technique description similarity only).

**Sub-task 4 — Entity match via TheHive REST (LLM + thehive4py)**

Call `thehive.search_open_cases(observables, hostname, username)` to find potentially
related open cases. The LLM then reasons about match strength:

- Shared **rare hash** → high confidence match (rare IOC = almost certainly same threat)
- Shared **hostname** + temporal proximity (< 24h) → medium confidence
- Shared **common domain** like `github.com` → low confidence / likely noise
- Shared hostname with > 7 day gap → investigate before merging

Observable rarity assessment: if an observable appears in >3 open cases, treat it as
infrastructure noise, not a correlation signal.

**Sub-task 5 — Kill-chain progression (LLM + Qdrant)**

If a candidate merge case is found, the LLM checks whether this alert represents a
later MITRE kill-chain stage than what the case already documents.

Using `qdrant_retrieve("mitre", ...)` to retrieve tactic-technique relationships, the
LLM answers: "does this alert introduce a new kill-chain stage for the same host?"

Example: existing case has T1566.001 (Phishing, Initial Access). New alert has
T1059.001 (PowerShell, Execution). Same host. → Progression, merge with high
confidence.

**Sub-task 6 — Mode decision**

Output `CorrelationResult`:
```json
{
  "action": "new | merge | deduplicated",
  "mode": "new | merge",
  "reason": "no_match | entity_match | kill_chain_progression",
  "confidence": "high | medium | low",
  "existing_case_context": { ... }  // only when action=merge
}
```

Confidence thresholds:
- `high` → proceed with merge
- `medium` → merge but flag for analyst review
- `low` → treat as new case, mention candidate in investigation notes

### Tools for Agent 1

| Tool | Implementation | Access pattern |
|------|---------------|----------------|
| TheHive full-alert fetch | `thehive4py` direct | Called by `main.py` before Agent 1 runs |
| `sigma_rule_lookup` | `tools/sigma_rules.py` (filesystem) | First call for Sigma-sourced alerts |
| `qdrant_retrieve` | `tools/qdrant.py` | MITRE technique candidates, kill-chain context |
| `thehive_search` | `tools/thehive.py` (REST) | Search open/closed cases |

### Implementation note — single call vs ReAct loop

Agent 1's sub-tasks are mostly sequential with light tool use. A **short ReAct loop**
(max 4 tool calls) is recommended:
1. `sigma_rule_lookup` (if Sigma alert) — free MITRE tags
2. `qdrant_retrieve("mitre", ...)` — technique candidates
3. `thehive_search(mode="open", ...)` — entity match
4. `qdrant_retrieve("mitre", ...)` — kill-chain context (only if merge candidate found)

The LLM produces structured JSON output after the loop using the `PerceptionResult`
schema.

---

## 7. Agent 2 — Investigate

**Type:** LLM ReAct agent
**Location:** `nodes/investigate.py`

### Mission

Replicate what a senior SOC analyst does before making a verdict call. Gather ALL
evidence needed to assess this specific alert. Adapt strategy based on intermediate
findings. Mark gaps explicitly — never fill missing evidence with assumptions.

### Mode A — New alert

```
INPUT:  CanonicalAlert + PerceptionResult (Agent 1 output)
BUDGET: max 8 tool calls
OUTPUT: EvidencePackage (structured JSON)
FOCUS:  build complete picture from scratch
```

`EvidencePackage` fields:
```python
rule_context:       description, detection_logic, known_fp_conditions,
                    mitre_tags_from_source, severity_from_source
asset_context:      hostname, criticality, owner, department,
                    services, network_zone
threat_intel:       per-observable verdict, score, analyzer, details
                    (populated from TheHive Cortex reports first,
                     supplemented by selective cortex_analyze calls)
temporal_context:   related_alerts_same_host_24h,
                    related_alerts_same_user_24h,
                    related_alerts_shared_iocs,
                    behavioral_baseline_deviation
historical_context: similar_past_cases (verdict, similarity),
                    mitre_candidates_from_rag
investigation_gaps: fields not retrieved (budget or unavailability)
investigation_trace: tool call log (tool, params, result_summary)
```

### Mode B — Merge candidate

```
INPUT:  CanonicalAlert + PerceptionResult + existing_case_context
BUDGET: max 5 tool calls
OUTPUT: DeltaEvidence (structured JSON)
FOCUS:  what does this NEW alert add to the existing case?
        new IOCs? new host/user? new kill-chain stage?
        changed TI verdict? do NOT re-query what case already has.
```

### Tool call discipline

1. **Check Agent 1's Cortex reports first** — TheHive already has analyzer results
   from the initial alert creation. Don't re-run Cortex on observables already
   analyzed unless the result was inconclusive.
2. **Call cheapest tools first:** `sigma_rule_lookup` → `itop_asset_lookup` → ES
   queries → `cortex_analyze` (most expensive, reserve for high-value IOCs only).
3. **Skip common-infrastructure observables for Cortex:** `github.com`, `8.8.8.8`,
   Microsoft/Google CDN IPs, etc. → add to `investigation_gaps` as "skipped: common
   infrastructure".
4. **Stop early if verdict is already clear** (confirmed FP from rule logic + asset
   context). Mark remaining budget unused. Do not waste calls.
5. If a tool fails → fix parameters and retry ONCE, then mark as gap.

### Cortex integration — direct REST, not cortex-mcp (updated, supersedes earlier MCP plan)

Cortex-mcp was built, source-reviewed, and integrated (`tools/cortex_mcp.py`,
`langchain-mcp-adapters` over stdio transport) — then reverted. Root cause: the
deployed `cortex-mcp` (`solomonneas/cortex-mcp`) hardcodes `StdioServerTransport`
with no HTTP/SSE mode, and stdio transport requires the *client* to spawn the MCP
server as a **local child process**. `agent-service` runs on 172.20.24.224;
`cortex-mcp` is installed on 172.20.24.221. Stdio cannot cross VMs — there is no
way to make this work without either running cortex-mcp's server logic on
172.20.24.224 directly (defeating the point of a separate installation) or the
cortex-mcp project adding a network transport, neither of which was in scope.

Agent 2 instead calls `cortex_analyze` (`tools/cortex.py`, direct REST against
Cortex at `CORTEX_URL`) selectively, based on its own reasoning — same selective-
invocation goal as the original MCP plan (this replaces the blanket n8n Switch
node approach either way), just without the MCP layer:

Call `cortex_analyze` when:
- A hash observable has NO existing report in the TheHive fetch (new hash, never seen)
- An IP observable is from a non-well-known range and has no existing report
- A URL observable has no existing report and the domain is not well-known
- The investigation profile indicates TI enrichment is critical (network_threat,
  malicious_file)

Do NOT call `cortex_analyze` when:
- The observable already has a completed Cortex report from the TheHive fetch
- The observable is clearly common infrastructure (github.com, 8.8.8.8, etc.)
- Budget is nearly exhausted (< 2 calls remaining) and other evidence is sufficient

### Investigation profiles (guide tool selection)

| Profile | Source engine | Priority tools | Avoid |
|---------|--------------|---------------|-------|
| `network_threat` | Suricata | cortex_analyze (IPs/domains), itop, ES (connections) | process/user queries |
| `endpoint_behavior` | Sigma + process | sigma_rule_lookup, ES (process history), cortex_analyze (hashes), itop | network flows |
| `malicious_file` | YARA/Strelka | cortex_analyze (ALL hash types), ES (Zeek session origin), itop | process ancestry, user auth |
| `network_anomaly` | Sigma + network | sigma_rule_lookup, cortex_analyze (IPs/domains), itop | — |
| `log_anomaly` | Sigma, no net/proc | sigma_rule_lookup, ES (user/entity history), itop | — |
| `generic` | unknown | all tools | — |

### Output schema enforcement

The investigator prompt includes the exact `EvidencePackage` / `DeltaEvidence` JSON
schema. The agent MUST output valid JSON as its final message.

On JSON parse failure:
1. Extract evidence from tool-call trace: bucket each tool result into the right field
   (`sigma_rule_lookup` → `rule_context`, `itop_asset_lookup` → `asset_context`,
   `cortex_analyze` results → `threat_intel`, ES queries → `temporal_context`,
   `qdrant_retrieve` + `thehive_search` → `historical_context`)
2. If trace extraction also fails → return `EvidencePackage` with
   `investigation_gaps=["agent output parse failure"]`

### Tools for Agent 2

| Tool | Implementation | Notes |
|------|---------------|-------|
| `itop_asset_lookup` | `tools/itop.py` (REST direct) | JSON-RPC, iTop API |
| `elasticsearch_query` | `tools/elasticsearch.py` (REST direct) | alerts-so-*, process-*, network.flow-* |
| `thehive_search` | `tools/thehive.py` (REST direct) | open + closed case history |
| `sigma_rule_lookup` | `tools/sigma_rules.py` (filesystem) | reads /opt/so/rules/sigma/ |
| `qdrant_retrieve` | `tools/qdrant.py` | MITRE, CVE, playbook retrieval |
| `cortex_analyze` | `tools/cortex.py` (direct REST) | selective IOC analysis — cortex-mcp reverted, see above |

---

## 8. Agent 3 — Analyze and Decide

**Type:** Single LLM call, NO tools
**Location:** `nodes/analyze.py`

### Mission

Receive Agent 2's structured evidence. Make the call. Reason like a senior analyst.
Show your work. Never invent evidence. Never fill gaps with assumptions.

### The prompt injection firewall

Agent 3 never sees raw logs, raw API responses, or attacker-controlled strings. Agent
2 summarized everything into typed fields. This is the architectural defense against
prompt injection: by the time text reaches Agent 3, it has been processed into
structured schema fields (`rule_context.description: str`, `asset_context.criticality:
str`, etc.), not arbitrary strings from the wire.

### Evidence summarization before LLM call

`nodes/analyze.py`'s `_summarize_evidence()` function truncates and structures the
evidence before sending to the LLM:
- `threat_intel` details truncated to 300 chars each
- `temporal_context` reduced to counts, not raw alert lists
- `historical_context` reduced to counts + verdicts, not full case objects

### Mode A — New alert output (TriageVerdict)

7-step reasoning process:

1. **Likelihood** (`unlikely | possible | likely | near_certain`): based on TI
   verdicts, rule FP conditions, behavioral context, temporal clustering, historical
   cases

2. **Impact if true** (`minor | moderate | severe | critical`): based on asset
   criticality, technique severity, scope, data sensitivity

3. **MITRE mapping** (validate/refine Agent 1's mapping): each entry gets
   `{tactic, technique, sub_technique|null, confidence, basis}`. Confidence capped at
   evidence quality. Sub-technique only when evidence specifically supports it.

4. **Verdict** (`true_positive | false_positive | needs_review`): synthesized from
   all above

5. **Reasoning**: every claim cites a specific evidence field name
   e.g. `"asset_context.criticality=high drove impact assessment"`
   e.g. `"threat_intel[0].verdict=malicious confirmed true_positive"`

6. **Recommended action** (`create_case | close_fp | needs_review`)

7. **Summary**: 3-5 sentences, analyst-readable, no jargon inflation

### Mode B — Merge candidate output (DeltaVerdict)

Single question: does this new evidence materially change the case?

```json
{
  "severity_change": "medium → high | no_change",
  "new_mitre_stages": [{"tactic": "...", "technique": "..."}],
  "scope_change": "1 host → 3 hosts | no_change",
  "urgency": "escalate | routine_merge",
  "recommended_action": "merge_and_retier | merge_quiet",
  "reasoning": "cites delta_evidence fields specifically"
}
```

### Quality bar

A verdict is only as good as the evidence it cites. If `evidence_package` has gaps,
confidence must reflect that. `needs_review` expressed when uncertain is correct.
Overconfident verdicts on incomplete evidence are the primary failure mode.

### On JSON parse failure

- Mode new → fallback to `TriageVerdict(verdict="needs_review",
  reasoning="Analyst output failed to parse — flagged for manual review.")`
- Mode merge → fallback to `DeltaVerdict(urgency="routine_merge",
  recommended_action="merge_quiet", reasoning="parse failure")`

---

## 9. Format Output Node

**Type:** Pure Python, no LLM
**Location:** `nodes/format_output.py`

### Severity lookup table

```
                  minor    moderate   severe    critical
unlikely          low      low        medium    medium
possible          low      medium     high      high
likely            medium   high       high      critical
near_certain      medium   high       critical  critical
```

Severity is computed from this table. **It is never a free model output.**

### Four code paths

1. **DEDUPLICATED** — `correlation.action == "deduplicated"`: returns `TriageResult`
   with `action=deduplicated`, no verdict or severity.

2. **NEW** — `mode == "new"` and verdict is set: looks up severity from table, builds
   full `TriageResult` with likelihood, impact, MITRE mapping, reasoning, summary,
   evidence_package, investigation_trace.

3. **MERGE** — `mode == "merge"` and delta_verdict is set: extracts new severity from
   `severity_change` string (e.g. `"medium → high"` → `"high"`). Includes
   merge_into_case, severity_change, urgency.

4. **NO VERDICT** — fallback: returns `action=needs_review` with reasoning "No verdict
   produced by analysis node."

---

## 10. Case Action Step

**Type:** Post-approval function, NOT part of the automatic graph
**Location:** `nodes/case_action.py` (new file, stub for now)

This step only runs after an analyst explicitly approves the `TriageResult`. It must
require an `approved: bool` parameter regardless of caller.

```python
def execute_case_action(triage_result: TriageResult, approved: bool) -> dict:
    if not approved:
        raise ValueError("Case action requires explicit analyst approval")
    ...
```

### Action routing

| TriageResult.action | TheHive operation |
|--------------------|-------------------|
| `create_case` | Promote alert → case. Set title/severity/tags from TriageResult. Post investigation summary as case comment. |
| `close_fp` | Update alert status to "Ignored" (TheHive 5's built-in status for false positive / not actionable alerts — verified against the live 5.6.1 instance, which has no custom statuses; "FP" is not a valid value). Post reasoning as comment. |
| `merge_quiet` | Merge alert into `merge_into_case`. Post delta summary as comment. |
| `merge_and_retier` | Merge + update case severity + flag for urgent SOC notification. |

### Implementation

Uses `thehive4py` direct REST for all write operations. TheHive MCP `manage-entities`
was considered but rejected at this stage — it is BETA with known prompt-injection
risk. Direct `thehive4py` calls are deterministic, auditable, and do not depend on LLM
sampling for case write operations.

---

## 11. Tool Inventory

### `tools/thehive.py` — TheHive REST (thehive4py)

```python
get_full_alert_with_analysis(alert_id: str) -> dict
    """Fetch alert + observables + Cortex reports via TheHive extraData mechanism."""
    # Uses POST /api/v1/query with extraData=["reports"]
    # Returns: alert metadata, tags, observables[], each with reports{} field
    # IMPORTANT: verify exact extraData key name against your TheHive version's
    # Swagger UI before hardcoding — it has shifted across 5.0/5.1/5.2

search_open_cases(observables: list, host: str, user: str) -> list[dict]
    """Search open/in-progress cases sharing host, user, or observables."""

search_closed_cases(rule_uuid: str, observables: list) -> list[dict]
    """Search resolved/closed cases for historical context."""

get_case_full(case_id: str) -> dict
    """Fetch full case context for a known case_id."""
```

**Auth:** Bearer token via `THEHIVE_API_KEY`.

**Implementation note (updated, supersedes earlier `thehive4py` plan):** the
deployed client uses raw `requests` against TheHive's `/api/v1/query` and
REST endpoints directly, not `thehive4py`. This was verified working against
the live TheHive **5.6.1** instance, including a real API quirk: the v1 query
API rejects an object-keyed multi-query (`{"query": {"alert": [...],
"observables": [...]}}`) with `error.expected.jsarray` — alert metadata and
observables are fetched as two separate array-form queries and merged in
`get_full_alert_with_analysis()`. Since this is tested and confirmed against
production, it stays as-is; do not migrate to `thehive4py` without a concrete
reason (the earlier plan to use it was aspirational, not verified).

### `tools/cortex_mcp.py` — REVERTED, do not rebuild without a transport fix

`tools/cortex_mcp.py` was built, source-reviewed (clean: auth from env vars only
and never logged, no observable data written to console/disk, graceful top-level
catch on failure, no filesystem writes), integrated into `nodes/investigate.py`,
and then reverted in the same session. Root cause: `solomonneas/cortex-mcp`
hardcodes `StdioServerTransport` — no HTTP or SSE mode exists in its source.
Stdio transport requires the calling process to spawn the MCP server as a local
child process, which is impossible across a network boundary. `agent-service`
runs on 172.20.24.224; the cortex-mcp install is on 172.20.24.221. This is a hard
infrastructure constraint, not a configuration issue — do not re-attempt this
integration unless one of these changes: cortex-mcp gains a network transport
upstream, or agent-service is redeployed onto 172.20.24.221 itself.

**Cortex TI is provided by `tools/cortex.py` instead** — see that entry below.
Agent 2 still invokes it selectively (same goal the MCP plan had), just over
direct REST rather than through an MCP layer.

### `tools/cortex.py` — Cortex direct REST (requests)

```python
analyze_observable(observable_type: str, observable_value: str, timeout: int = 180) -> dict
    """Run the best available Cortex analyzer against an observable and return a
    verdict. Never raises — any failure (bad type, no analyzer, network error,
    timeout) comes back as a dict with verdict "unknown" and the problem in
    "details"."""
```

Picks an analyzer automatically (VirusTotal preferred, AbuseIPDB for IPs as a
second choice, otherwise the first available analyzer for the observable type),
submits the job, polls `waitreport`, and reduces the resulting taxonomies to a
single `{verdict, score, details, analyzer}` via worst-level-wins. Exposed to
Agent 2 as the `cortex_analyze` tool. This is now the **only** Cortex path — see
the `tools/cortex_mcp.py` entry above for why the MCP alternative was reverted.

**Auth:** Bearer token via `CORTEX_API_KEY`.

### `tools/elasticsearch.py` — Elasticsearch direct (elasticsearch-py)

```python
query_related_alerts(host: str, user: str, iocs: list, window: str = "24h") -> list
    """Query .ds-logs-detections.alerts-so-* for related alerts."""

query_process_history(host: str, user: str, window: str = "24h") -> list
    """Query .ds-logs-endpoint.process-* for process ancestry."""

query_connection_history(src_ip: str, dst_ip: str, window: str = "24h") -> list
    """Query .ds-logs-network.flow-* for network flows."""
```

**Auth:** API key via `ES_API_KEY`. Security Onion's Elasticsearch (port 9200) is
**closed to external hosts by default** — a firewall rule for `elasticsearch_rest`
must be added via Security Onion's SOC Config → Firewall → Hostgroups →
`elasticsearch_rest`. This is a prerequisite for the agent-service to reach ES.

API key must have **read-only** access scoped to the alert, process, and network
indices. It must NOT have write access to telemetry indices.

### `tools/qdrant.py` — Qdrant direct (qdrant-client + fastembed)

```python
retrieve_mitre(query_text: str, top_k: int = 5) -> list[dict]
    """Semantic search over MITRE ATT&CK techniques. Returns technique candidates."""

retrieve_playbooks(query_text: str, top_k: int = 3) -> list[dict]
    """Search SOC playbooks for relevant response procedures."""

retrieve_cve(query_text: str, top_k: int = 3) -> list[dict]
    """Search CVE database for vulnerability context."""
```

**Embedding (updated, supersedes earlier fastembed plan):** the deployed
`triage_kb` collection's vectors are 1024-dimensional, which doesn't match
any `fastembed`-supported model — verified empirically. The actual embedding
model is **`BAAI/bge-m3`**, loaded via raw `sentence-transformers`
(`SentenceTransformer(QDRANT_EMBEDDING_MODEL).encode(...)`), not
`qdrant-client[fastembed]`'s auto-embed convenience. A raw vector is passed
to `client.query_points(collection_name, query=<vector>, ...)`.

**Collections:** the deployed Qdrant has **one** collection, `triage_kb`
(2,412 points of MITRE + CVEs + playbooks combined), not three separate named
collections. MITRE/CVE/playbook records are distinguished by a `collection`
payload discriminator field (`mitre_attack` | `cve_intel` | `playbooks`) and
filtered with a `FieldCondition` at query time — see `tools/qdrant.py`.
Already populated. See `scripts/ingest_qdrant.py` for re-ingestion.

### `tools/itop.py` — iTop CMDB (requests, JSON-RPC)

```python
lookup_asset(hostname_or_ip: str) -> dict
    """Look up asset business context from iTop CMDB."""
    # Returns: found, hostname, criticality, status, location,
    #          organization, contacts, services, network_zone
```

**Auth:** JSON-RPC over HTTP with `ITOP_USER` / `ITOP_KEY` as form fields.

### `tools/sigma_rules.py` — Sigma rule lookup (filesystem)

```python
get_rule_source(rule_uuid: str) -> dict
    """Read Sigma rule YAML from disk by UUID. Returns rule metadata + MITRE tags."""
    # Walks SIGMA_RULES_PATH recursively for .yml/.yaml files
    # Matches data.get("id") against requested UUID
    # Returns: title, description, falsepositives[], tags[attack.txxxx], level,
    #          detection, logsource, references
```

**Dependency:** `SIGMA_RULES_PATH=/opt/so/rules/sigma` must be accessible from the
agent-service container/host. Mount as read-only volume if containerized.

---

## 12. Schemas — All Pydantic Models

All models in `schemas.py`.

### Input models

```python
class AlertWebhookPayload(BaseModel):
    thehive_alert_id: str
    raw_alert: dict           # n8n Alert Builder output
    asset_context: dict = {}  # iTop response

class TriageRequest(BaseModel):
    """Legacy — for direct testing without TheHive fetch."""
    canonical_alert: CanonicalAlert
```

### CanonicalAlert and sub-models

```python
class Rule(BaseModel):
    name: str
    uuid: Optional[str]
    native_severity: int              # 1-4 (TheHive scale)
    category: Optional[str]
    product: Optional[str]
    source_engine: str                # "sigma" | "suricata" | "yara" | "unknown"

class Host(BaseModel):
    hostname: str
    ip: list[str] = []
    os: dict = {}

class User(BaseModel):
    name: Optional[str]
    id: Optional[str]

class Network(BaseModel):
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    bytes_total: Optional[int]
    packets_total: Optional[int]

class Process(BaseModel):
    pid: Optional[int]
    name: Optional[str]
    path: Optional[str]
    command_line: Optional[str]
    parent_pid: Optional[int]
    parent_name: Optional[str]

class File(BaseModel):
    name: Optional[str]
    path: Optional[str]
    size: Optional[int]
    mime_type: Optional[str]

class HashBundle(BaseModel):
    md5: list[str] = []
    sha1: list[str] = []
    sha256: list[str] = []
    sha512: list[str] = []
    imphash: list[str] = []

class Observables(BaseModel):
    external_ips: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    hashes: HashBundle = HashBundle()

class CortexResult(BaseModel):
    observable: str
    type: str
    verdict: str                       # malicious | suspicious | safe | unknown
    score: float
    details: str
    analyzer: str
    raw: dict = {}

class CanonicalAlert(BaseModel):
    alert_id: str
    timestamp: str
    source_engine: str
    investigation_profile: str         # network_threat | endpoint_behavior |
                                       # malicious_file | network_anomaly |
                                       # log_anomaly | generic
    rule: Rule
    host: Host
    user: User = User()
    network: Optional[Network]
    process: Optional[Process]
    file: Optional[File]
    observables: Observables = Observables()
    cortex_results: list[CortexResult] = []    # pre-populated from TheHive fetch
    thehive_alert_id: str
    thehive_observable_ids: list[str] = []
    asset_context: dict = {}
```

### Correlation models

```python
class ExistingCaseContext(BaseModel):
    case_id: str
    title: str
    severity: str                      # low | medium | high | critical
    summary: str = ""

class CorrelationResult(BaseModel):
    action: str                        # new | merge | deduplicated
    mode: str                          # new | merge
    reason: str                        # no_match | entity_match |
                                       # kill_chain_progression | exact_duplicate
    confidence: str = "high"           # high | medium | low
    existing_case_context: Optional[ExistingCaseContext] = None
    deduplicated: bool = False         # DEPRECATED — use action == "deduplicated"
```

### Agent output models

```python
class InvestigationTraceEntry(BaseModel):
    tool: str
    params: dict
    result_summary: str

ToolCallLogEntry = InvestigationTraceEntry   # alias for backward compat

class EvidencePackage(BaseModel):
    rule_context: dict = {}
    asset_context: dict = {}
    threat_intel: list[dict] = []
    temporal_context: dict = {}
    historical_context: dict = {}
    investigation_gaps: list[str] = []
    investigation_trace: list[InvestigationTraceEntry] = []

class DeltaEvidence(BaseModel):
    new_iocs: list[str] = []
    new_hosts: list[str] = []
    new_users: list[str] = []
    new_kill_chain_stages: list[dict] = []
    changed_ti_verdicts: list[dict] = []
    additional_context: dict = {}
    investigation_gaps: list[str] = []
    investigation_trace: list[InvestigationTraceEntry] = []

class MitreMapping(BaseModel):
    tactic: str
    technique: str
    sub_technique: Optional[str] = None
    confidence: str                    # high | medium | low
    basis: str                         # evidence citation

class TriageVerdict(BaseModel):
    likelihood: str                    # unlikely | possible | likely | near_certain
    impact_if_true: str                # minor | moderate | severe | critical
    verdict: str                       # true_positive | false_positive | needs_review
    mitre_mapping: list[MitreMapping] = []
    reasoning: str
    recommended_action: str            # create_case | close_fp | needs_review
    summary: str

class DeltaVerdict(BaseModel):
    severity_change: str = "no_change"
    new_mitre_stages: list[dict] = []
    scope_change: str = "no_change"
    urgency: str = "routine_merge"     # escalate | routine_merge
    recommended_action: str = "merge_quiet"
    reasoning: str = ""
```

### Perception result (Agent 1 output)

```python
class PerceptionResult(BaseModel):
    canonical_alert: CanonicalAlert
    mitre_mapping: list[MitreMapping]
    correlation_result: CorrelationResult
```

### Type aliases

```python
from typing import Literal
Likelihood = Literal["unlikely", "possible", "likely", "near_certain"]
Impact     = Literal["minor", "moderate", "severe", "critical"]
Severity   = Literal["low", "medium", "high", "critical"]
```

### Final output model

```python
class TriageResult(BaseModel):
    alert_id: str
    action: str                        # create_case | close_fp | needs_review |
                                       # merge_quiet | merge_and_retier | deduplicated
    verdict: Optional[str] = None
    severity: Optional[str] = None
    likelihood: Optional[str] = None
    impact_if_true: Optional[str] = None
    mitre_mapping: list[dict] = []
    reasoning: str = ""
    summary: str = ""
    merge_into_case: Optional[str] = None
    severity_change: Optional[str] = None
    urgency: Optional[str] = None
    evidence_package: dict = {}
    investigation_trace: list[InvestigationTraceEntry] = []
    correlation_result: Optional[dict] = None
```

### LangGraph state

```python
class TriageState(TypedDict):
    canonical_alert: CanonicalAlert
    mode: str                          # new | merge
    perception_result: Optional[PerceptionResult]
    correlation_result: Optional[CorrelationResult]
    existing_case_context: Optional[ExistingCaseContext]
    evidence_package: Optional[EvidencePackage]
    delta_evidence: Optional[DeltaEvidence]
    triage_verdict: Optional[TriageVerdict]
    delta_verdict: Optional[DeltaVerdict]
    triage_result: Optional[TriageResult]
```

---

## 13. LangGraph State Machine

**Location:** `graph.py`

```python
from langgraph.graph import StateGraph, END
from nodes.perceive import gate0_dedup, perceive
from nodes.investigate import investigate
from nodes.analyze import analyze
from nodes.format_output import format_output

def _route_after_gate0(state: TriageState) -> str:
    if state["correlation_result"] and \
       state["correlation_result"].action == "deduplicated":
        return "format_output"
    return "perceive"

def _route_after_perceive(state: TriageState) -> str:
    corr = state["correlation_result"]
    if corr and corr.action == "deduplicated":
        return "format_output"
    return "investigate"

builder = StateGraph(TriageState)
builder.add_node("gate0", gate0_dedup)
builder.add_node("perceive", perceive)
builder.add_node("investigate", investigate)
builder.add_node("analyze", analyze)
builder.add_node("format_output", format_output)

builder.set_entry_point("gate0")
builder.add_conditional_edges("gate0", _route_after_gate0, {
    "format_output": "format_output",
    "perceive": "perceive",
})
builder.add_conditional_edges("perceive", _route_after_perceive, {
    "format_output": "format_output",
    "investigate": "investigate",
})
builder.add_edge("investigate", "analyze")
builder.add_edge("analyze", "format_output")
builder.add_edge("format_output", END)

graph = builder.compile()
```

---

## 14. Technology Stack — Final Decisions

Every decision below was made after deliberate comparison. Do not change without
re-reading the rationale in `architecture-revision-v2.md`.

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **LLM** | Qwen3 30B-A3B via Ollama | MoE: 30B quality, 3B inference speed. CPU-only with 64GB RAM at 12-22 tok/s. Best Ollama model for agentic tool calling at this hardware tier. |
| **LLM serving** | Ollama (CPU, 16 cores, 64GB RAM) | No GPU. Qwen3 30B-A3B at Q4_K_M ≈ 17GB RAM. Leaves 47GB for OS + services. |
| **Agent framework** | LangGraph + LangChain | Stateful graph with conditional routing. Already in codebase. |
| **Vector DB / RAG** | Qdrant (keep) | Already deployed at 172.20.24.224:6333, 2,412 points ingested in a single `triage_kb` collection with a `collection` discriminator field. Embeddings are `BAAI/bge-m3` (1024-dim) via raw `sentence-transformers` (verified empirically — the deployed vectors don't match any fastembed-supported model). No production ES cluster risk. Migrate to ES later if hybrid retrieval proves necessary. |
| **Telemetry queries** | Elasticsearch direct (`elasticsearch-py`) | Security Onion's ES at 172.20.24.58. Read-only API key. Port 9200 firewall rule required. |
| **TheHive access** | raw `requests` direct REST | Verified against the live 5.6.1 instance. Deterministic, no BETA risk. All reads and writes via direct API calls to `/api/v1/...`. (Earlier plan specified `thehive4py`; superseded — raw `requests` is what's tested and deployed.) |
| **Cortex access** | `tools/cortex.py`, direct REST (`requests`) | Selective analyzer invocation replacing blanket n8n Switch node, driven by Agent 2's own reasoning. `cortex-mcp` (solomonneas) was built, source-reviewed, and integrated, then reverted: it hardcodes stdio transport with no HTTP/SSE mode, and agent-service (172.20.24.224) and cortex-mcp (172.20.24.221) are on different VMs — stdio can't cross that boundary. See §11's `tools/cortex_mcp.py` entry. |
| **iTop access** | `requests` direct (JSON-RPC) | No alternative client. Existing `tools/itop.py` works. |
| **Sigma rules** | Filesystem (`pyyaml`) | Local read from `/opt/so/rules/sigma/`. Existing `tools/sigma_rules.py` works. |
| **Case management writes** | `thehive4py` direct | Deterministic, auditable. TheHive MCP `manage-entities` considered but rejected: BETA, prompt-injection risk, requires TheHive 5.5+. |
| **Dedup** | Redis | Optional. Service boots and functions without Redis; dedup check is skipped. |

### Rejected decisions (and why)

| Decision | Rejected | Reason |
|----------|---------|--------|
| Replace Qdrant with Elasticsearch for knowledge base | Rejected | Production ES cluster resource contention risk, ILM management overhead, Qdrant already deployed and working. Revisit if hybrid retrieval quality proves insufficient. |
| TheHive MCP for case search | Rejected for current corpus | Case corpus is machine-generated agent verdicts — structured REST queries outperform NL→filter translation on uniformly-structured data. Reconsider when analysts add narrative summaries. |
| TheHive MCP `manage-entities` for writes | Rejected | BETA, known prompt-injection risk, TheHive 5.5+ requirement unconfirmed. |
| `llama3.2:3b` (current `.env`) | Replaced | 3B too small for reliable multi-step tool calling and structured JSON output across 3 agents. |
| 2-agent merged architecture | Not needed | Qwen3 30B-A3B on 64GB RAM supports full 3-agent architecture. |
| Elasticsearch MCP for telemetry | Not needed | Direct `elasticsearch-py` is simpler for deterministic Query DSL queries. MCP adds infrastructure without benefit for single-consumer agent. |
| `cortex-mcp` for Cortex TI (Phase 4) | Reverted after implementation | Built, source-reviewed, and integrated — then reverted. `solomonneas/cortex-mcp` hardcodes `StdioServerTransport`, no HTTP/SSE mode. Stdio requires spawning the server as a local child process; agent-service (172.20.24.224) and cortex-mcp (172.20.24.221) are on different VMs. Not a config fix — a hard transport/topology mismatch. Reverted to direct REST (`tools/cortex.py`), same selective-invocation behavior. |

---

## 15. File Tree

```
agent-service/
├── main.py
│     FastAPI app
│     POST /triage → AlertWebhookPayload → TriageResult
│     GET  /health → {"status": "ok", "timestamp": "...", "service": "agent-service"}
│     Calls thehive.get_full_alert_with_analysis()
│     Calls alert_builder.build_canonical_alert()
│     Calls graph.invoke(initial_state)
│
├── graph.py
│     LangGraph StateGraph
│     Nodes: gate0 → perceive → investigate → analyze → format_output
│     Conditional edges: deduplicated → format_output (skip agents)
│
├── alert_builder.py              ← NEW
│     build_canonical_alert(raw_alert, hive_alert, asset_context) → CanonicalAlert
│     Handles observable dataType sanity checks
│     Maps Cortex reports to CortexResult schema
│     Parses tags for hostname, agent_id, rule_uuid
│
├── config.py
│     Typed Settings dataclass via python-dotenv
│     Required: CORTEX_URL, CORTEX_API_KEY, THEHIVE_URL, THEHIVE_API_KEY,
│              ITOP_URL, ITOP_USER, ITOP_KEY, ES_URL, LLM_BASE_URL, LLM_MODEL
│     Optional: ES_API_KEY, LLM_API_KEY, QDRANT_URL, REDIS_URL,
│              SIGMA_RULES_PATH, CORTEX_MCP_URL,
│              MAX_TOOL_CALLS_NEW (default 8),
│              MAX_TOOL_CALLS_MERGE (default 5),
│              DEDUP_WINDOW_SECONDS (default 300)
│
├── schemas.py
│     All Pydantic models (see §12)
│     AlertWebhookPayload (new), PerceptionResult (new)
│     TriageRequest (legacy, keep for tests)
│     ExistingCaseContext, CorrelationResult
│     CanonicalAlert and sub-models
│     EvidencePackage, DeltaEvidence
│     TriageVerdict, DeltaVerdict, MitreMapping
│     TriageResult, TriageState
│     Literal type aliases: Likelihood, Impact, Severity
│     ToolCallLogEntry = InvestigationTraceEntry (alias)
│
├── requirements.txt
│     fastapi, uvicorn, langgraph, langchain, langchain-openai
│     langchain-mcp-adapters, pydantic, requests, python-dotenv
│     elasticsearch, qdrant-client[fastembed], thehive4py
│     redis, pyyaml, httpx
│
├── .env                          (gitignored)
│
├── nodes/
│   ├── __init__.py
│   ├── perceive.py               ← RENAMED/REBUILT from correlate.py
│   │     gate0_dedup()           → Redis fingerprint check (pure Python)
│   │     perceive()              → Agent 1 LLM loop (6 sub-tasks)
│   │
│   ├── investigate.py            ← EXISTS, needs structured output fix
│   │     Agent 2 ReAct loop
│   │     Uses cortex_analyze (direct REST) selectively — no cortex-mcp, see §11
│   │     Removes raw elasticsearch calls (uses tools/elasticsearch.py directly)
│   │     Enforces structured JSON output
│   │
│   ├── analyze.py                ← EXISTS, mostly solid
│   │     Agent 3 single LLM call
│   │     Receives Agent 1 mitre_mapping for two-pass validation
│   │
│   ├── format_output.py          ← EXISTS, minor fixes needed
│   │     Fix: use action == "deduplicated" not correlation.deduplicated
│   │     Fix: Literal type imports now exist in schemas.py
│   │
│   └── case_action.py            ← NEW, stub
│         execute_case_action(triage_result, approved) → dict
│
├── tools/
│   ├── __init__.py
│   ├── thehive.py                ← EXISTS, add get_full_alert_with_analysis()
│   ├── cortex.py                 ← EXISTS, direct REST — the only Cortex path
│   │                                (cortex_mcp.py was built + reverted, see §11:
│   │                                 stdio transport can't cross the agent-service/
│   │                                 cortex-mcp VM boundary)
│   ├── itop.py                   ← EXISTS, no changes needed
│   ├── elasticsearch.py          ← EXISTS, keep (no MCP replacement)
│   ├── sigma_rules.py            ← EXISTS, no changes needed
│   └── qdrant.py                 ← EXISTS, no changes needed
│
├── prompts/
│   ├── __init__.py
│   ├── perceiver.py              ← NEW, replaces investigator.py for Agent 1
│   │     build_prompt(mode) → Agent 1 system prompt
│   │     Output schema: PerceptionResult JSON
│   │
│   ├── investigator.py           ← EXISTS, update output schema
│   │     Add EvidencePackage / DeltaEvidence JSON schema to prompt
│   │     Remove qdrant_retrieve reference to old Cortex tool
│   │
│   └── analyst.py                ← EXISTS, add mitre_mapping validation instruction
│
├── scripts/
│   ├── __init__.py
│   └── ingest_qdrant.py          ← EXISTS, no changes needed
│
└── tests/
    ├── test_schemas.py           update for new models
    ├── test_graph.py             update for perceive node rename
    ├── test_perceive.py          ← NEW
    ├── test_correlate.py         ← RETIRE or repurpose
    ├── test_format_output.py     update for action string fix
    ├── test_analyze.py           update for mitre_mapping two-pass
    ├── test_alert_builder.py     ← NEW, test observable type correction
    └── test_prompts.py           update for perceiver prompt
```

---

## 16. Environment Configuration

```ini
# Required
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
LLM_MODEL=qwen3:30b-a3b           # CHANGED from llama3.2:3b

# Required for Qdrant RAG
QDRANT_URL=http://172.20.24.224:6333

# Required for Sigma rule lookup
SIGMA_RULES_PATH=/opt/so/rules/sigma

# Optional
LLM_API_KEY=sk-no-auth            # Ollama doesn't need one but LangChain requires it
ES_API_KEY=<base64-key>
REDIS_URL=redis://localhost:6379   # skip for no dedup
MAX_TOOL_CALLS_NEW=8
MAX_TOOL_CALLS_MERGE=5
DEDUP_WINDOW_SECONDS=300
```

### Critical infrastructure prerequisite

Security Onion's Elasticsearch (port 9200) is **blocked by default** for external
hosts. Before the agent-service can query ES, add the firewall rule:

```
SOC Console → Configuration → Firewall → Hostgroups → elasticsearch_rest
→ Add agent-service IP/subnet
→ Options → Synchronize Grid
```

---

## 17. Key Architectural Decisions and Rationale

### Decision 1: correlate.py becomes perceive.py (LLM-powered)

**Why:** Three problems that cannot be solved with deterministic code:
- Variant metadata across Suricata/Sigma/YARA requires LLM normalization
- Sigma MITRE tags not in alert documents requires inference
- Case correlation requires reasoning about match strength, not string equality

Research validation: AgentSOC uses a dedicated Perception Layer for normalization.
CORTEX uses a behavior-analysis agent for correlation. Every modern SOC triage
framework uses LLM reasoning for these tasks.

### Decision 2: Selective Cortex invocation by Agent 2, not n8n Switch node

**Why:** Confirmed operational pain point — blanket analyzer triggering adds latency
and wastes quota on low-value observables (github.com, common domains). Agent 2
invokes Cortex selectively based on observable priority and context. A static
Switch node cannot reason about whether an observable is worth analyzing.

**Updated:** the original plan routed this through `cortex-mcp` for selective
invocation. That was built, source-reviewed, and integrated, then reverted —
`cortex-mcp` hardcodes stdio transport, which can't cross the VM boundary between
agent-service (172.20.24.224) and cortex-mcp (172.20.24.221). The selective-
invocation *goal* stands; it's implemented via Agent 2 calling `cortex_analyze`
(direct REST, `tools/cortex.py`) selectively instead. See §11's `tools/cortex_mcp.py`
entry for the full root-cause writeup.

### Decision 3: Qdrant stays, ES not used for knowledge base

**Why:** Qdrant is already deployed, already populated (2,412 points), and
FastEmbed handles automatic query embedding. Adding a knowledge base index to
Security Onion's production ES cluster introduces compute overhead from vector
indexing (batch offline, but still), ILM policy management to exclude knowledge
indices from telemetry retention, and potential cluster resource contention. The
operational simplicity argument for a single cluster was valid in theory but
outweighed by the risk to production telemetry at this deployment scale. Revisit
if hybrid retrieval (BM25 + vector) proves necessary for MITRE mapping quality.

### Decision 4: Qwen3 30B-A3B on Ollama

**Why:** 64GB RAM, 16 cores, no GPU. The Qwen3 30B-A3B MoE model activates only 3B
parameters per token — inference at 3B speed with 30B quality. At Q4_K_M (~17GB
RAM), fits comfortably with 47GB headroom for OS and services. Reports show 12-22
tok/s on CPU-only systems. Reliable structured JSON output and tool calling for
agentic loops. Upgrade path to Qwen3 8B dense if MoE proves unstable on this
hardware.

### Decision 5: TheHive MCP rejected for case search

**Why:** The case corpus consists of machine-generated agent verdicts, not human
narratives. Structured REST queries outperform NL→filter translation on uniformly
structured data. TheHive MCP `search-entities` adds a non-determinism layer for no
retrieval quality gain on this specific corpus. Additionally: TheHive MCP is BETA
(known prompt-injection risk per StrangeBee). Reconsider if analysts begin writing
narrative case summaries.

### Decision 6: Two-pass MITRE mapping

Agent 1 produces initial MITRE mappings from alert context (fast, approximate).
Agent 3 validates and potentially refines these against the full evidence package
gathered by Agent 2 (slower, more accurate). This is the hybrid approach recommended
in "Labeling NIDS Rules with MITRE ATT&CK Techniques: ML vs. LLMs" (arXiv
2412.10978) — initial mapping from context, refined against evidence.

---

## 18. Implementation Bugs to Fix First

Before building any new functionality, fix these bugs that prevent the current
pipeline from running. Fix them in Phase 1 of the build order.

| # | Bug | File | Fix |
|---|-----|------|-----|
| 1 | Redis crashes at import if `REDIS_URL` unset | `correlate.py` | Lazy init, null-safe guard |
| 2 | `ExistingCaseContext` imported but not in `schemas.py` | `correlate.py` | Add model to `schemas.py` |
| 3 | `CorrelationResult` has no `deduplicated` field but it's set | `correlate.py` | Use `action="deduplicated"` everywhere |
| 4 | `format_output.py` checks `correlation.deduplicated` | `format_output.py` | Change to `correlation.action == "deduplicated"` |
| 5 | `Impact`, `Likelihood`, `Severity` imported but not defined | `format_output.py` | Add Literal aliases to `schemas.py` |
| 6 | `ToolCallLogEntry` imported but model is `InvestigationTraceEntry` | `investigate.py` | Add alias in `schemas.py` |
| 7 | Agent output stored as raw text in `rule_context["agent_notes"]` | `investigate.py` | Enforce structured JSON output (Phase 5) |
| 8 | `LLM_MODEL=llama3.2:3b` in `.env` | `.env` | Change to `qwen3:30b-a3b` |

---

## 19. Build Order

```
PHASE 1 — Fix existing bugs (get baseline running)
  Fix bugs 1-6 from §18
  Confirm: pytest tests/ -v passes
  Confirm: alert-sample.json completes POST /triage without 500

PHASE 2 — New input contract
  Add AlertWebhookPayload to schemas.py
  Add get_full_alert_with_analysis() to tools/thehive.py
    (verify extraData key name against live TheHive Swagger UI first)
  Create alert_builder.py with build_canonical_alert()
    (include observable dataType sanity check)
  Update main.py to accept AlertWebhookPayload
  Test: POST /triage with real n8n sample payload, confirm CanonicalAlert built

PHASE 3 — Agent 1 (perceive.py)
  Rename nodes/correlate.py → nodes/perceive.py
  Keep gate0_dedup() as pure Python Redis check
  Build perceive() LLM agent (6 sub-tasks)
  Create prompts/perceiver.py with PerceptionResult output schema
  Add PerceptionResult to schemas.py
  Update graph.py: replace correlate node with gate0 + perceive nodes
  Test: 10 real alerts, check CanonicalAlert quality + MITRE mapping accuracy

PHASE 4 — Cortex integration (DONE — cortex-mcp attempted and reverted)
  Built tools/cortex_mcp.py wrapping solomonneas/cortex-mcp (source reviewed first)
  Added cortex-mcp tools to nodes/investigate.py tool list
  Discovered: cortex-mcp hardcodes stdio transport, agent-service (172.20.24.224)
    and cortex-mcp (172.20.24.221) are on different VMs — stdio can't cross that
  Reverted: removed tools/cortex_mcp.py, restored tools/cortex.py (direct REST)
    as Agent 2's Cortex path, same selective-invocation behavior
  Test: verify selective invocation (github.com skipped, rare hash analyzed)

PHASE 5 — Agent 2 structured output (DONE)
  prompts/investigator.py already had the EvidencePackage/DeltaEvidence JSON
    schema and structured-output enforcement from earlier work — no change needed
  nodes/investigate.py already had fallback-from-trace (_build_from_tool_results)
    — no change needed
  Added: explicit "Existing Cortex results" block in Agent 2's human message
    (previously only implicit via the full alert JSON dump) + a deterministic
    _merge_cortex_results() that guarantees Agent 1's pre-fetched Cortex data
    survives into the final EvidencePackage.threat_intel regardless of whether
    the LLM's JSON output echoes it back — including on total agent failure
    (_fallback_state now seeds threat_intel from existing_cortex_results too)
  Removed dead code: _gap_msg() and _fallback_extract() had zero call sites
  Fixed a latent bug: _to_cortex_results()'s except-fallback path re-used the
    same malformed score value via item.get(), so it threw the same
    ValidationError it was supposed to catch — added _coerce_score()
  Test: tests/test_investigate.py added (17 tests) — investigate.py had no
    dedicated test file before this phase

PHASE 6 — Agent 3 two-pass MITRE (DONE)
  Updated nodes/analyze.py: mode="new" now reads state["mitre_mapping"] (Agent 1's
    output, set by nodes/perceive.py) and includes it as agent1_initial_mitre_mapping
    in the human message sent to Agent 3, ahead of evidence_package_summary
  Updated prompts/analyst.py: Step 3 rewritten as an explicit validate-and-refine
    instruction (keep+recompute confidence if evidence confirms, drop/downgrade if
    contradicted, add if evidence reveals something Agent 1 missed) instead of
    "produce a mapping from scratch"
  TriageVerdict.mitre_mapping already came from Agent 3's own parsed JSON output
    (TriageVerdict(**parsed)), never a pass-through of Agent 1's — that invariant
    held before this phase, just needed Agent 3 to actually see Agent 1's mapping
    to validate against
  Merge mode untouched — DeltaVerdict.new_mitre_stages is a different concept
    (new kill-chain stages introduced by the delta), not full-mapping validation
  Test: tests/test_analyze.py — 3 new tests mocking nodes.analyze._llm (first
    LLM-in-the-loop test coverage for this module) verifying agent1's mapping
    reaches the prompt, the final mapping is Agent 3's own output not a
    pass-through, and the missing-mapping case degrades gracefully

PHASE 7 — Fix format_output.py + end-to-end test (DONE — verification only, nothing to fix)
  Bug 3 (action string consistency) and bug 4 (deduplicated check) were both
    already fixed by the time Phase 1 was reached (see §18 table + CHANGES.md) —
    verified again here: format_output.py checks corr.action == "deduplicated"
    correctly, no boolean field exists on CorrelationResult to confuse it with
  Verified §18 bug 5 (Impact/Likelihood/Severity Literal aliases) is not a live
    bug: grepped the full codebase, nothing imports those names anywhere
  Test full graph: real alert in → TriageResult out. tests/test_e2e.py added —
    POST /triage via FastAPI's TestClient with alert-sample.json's raw Security
    Onion webhook body converted into the AlertWebhookPayload.raw_alert shape
    n8n actually sends (§3), all 6 external dependencies mocked (TheHive fetch,
    Agent 1/2's ReAct-loop LLM, Agent 3's direct LLM call — Qdrant/ES/iTop/Cortex
    are only reachable through the mocked ReAct loops, so covered transitively).
    Confirms a full new-mode run (gate0 → perceive → investigate → analyze →
    format_output) returns 200 with a well-formed TriageResult, and that a
    deduplicated result short-circuits before investigate's agent is ever
    constructed.

PHASE 8 — Case action stub (DONE — not wired into graph.py, as intended)
  Created nodes/case_action.py with execute_case_action(triage_result, approved)
    -> dict. Raises ValueError immediately if approved is False, before any
    TheHive call. Four branches keyed on triage_result.action: create_case
    (promote alert -> case, set title/severity/tags, post investigation summary
    as comment), close_fp (update alert status, post reasoning as comment),
    merge_quiet (merge alert into case, post delta summary as comment),
    merge_and_retier (merge + update case severity + urgent_notification_required
    flag in the result — actual notification delivery is out of scope for a
    TheHive-only module). Unknown actions return {"status": "skipped", ...}
    rather than raising.
  Implemented via direct REST (tools/thehive.py), not thehive4py and not TheHive
    MCP — consistent with Decision 5 and the tools/thehive.py precedent set in
    Phase 2. New write functions added: promote_alert_to_case, update_case,
    add_case_comment, update_alert_status, add_alert_comment,
    merge_alert_into_case. Endpoint paths follow TheHive 5's documented v1 REST
    API shape and are UNVERIFIED against the live instance (unlike
    get_full_alert_with_analysis) — confirm against the live Swagger UI before
    this is ever wired into a real approval flow. One specific value IS
    verified: close_fp sets the alert status to "Ignored", not "FP" — checked
    against the live 5.6.1 instance's UI, which has no custom statuses
    configured (only the built-in New, Updated, Ignored, Imported; "FP" is not
    a valid value).
  Not added to tools/registry.py's TOOLS — these are write operations, never
    exposed to the LLM agents, preserving "all agent tools are read-only"
  Test: tests/test_case_action.py (11 tests) — approved=False raises before any
    TheHive call, all four branches call the right operations with the right
    arguments (mocking tools/thehive.py), missing merge_into_case on the merge
    branches returns a clean error dict, unknown/deduplicated actions skip
    gracefully

PHASE 9 — n8n integration updates (DOCUMENTED — n8n isn't in this repo, see
    N8N-INTEGRATION.md for the full migration guide; nothing applied to a live
    n8n instance from here)
  Remove Switch1 + per-type Cortex analyzer nodes — documented
  Add HTTP POST to /triage with slim AlertWebhookPayload — documented, with
    the exact raw_alert shape and a note that the observable-ID fetch step is
    also no longer needed (get_full_alert_with_analysis() fetches it itself)
  Add Switch on triage_result.action → case action branches — documented,
    including the "Ignored" not "FP" status fix from the same session
  Clarified a boundary that isn't obvious from the code alone: n8n still
    performs the actual TheHive writes today — nodes/case_action.py exists but
    isn't wired into graph.py/main.py, so nothing calls it yet
  Test: live Security Onion alert → n8n → agent-service → TheHive case created
    — a testing checklist is in N8N-INTEGRATION.md §8; actual execution
    requires a live n8n + TheHive + Security Onion environment not reachable
    from this session

PHASE 10 — Tests
  Update test_schemas.py for all new models
  Create test_perceive.py (mock TheHive, Qdrant, ES)
  Create test_alert_builder.py (observable type correction coverage)
  Update test_format_output.py (action string fix)
  Update test_analyze.py (two-pass MITRE)
  pytest tests/ -v — all green before shipping

PHASE 11 — Tier 0 validation (advisory only)
  Every verdict annotates the case, nothing auto-acts
  Analyst reviews all TriageResults
  Track agreement rate (Cohen's κ)
  Do not move to Tier 1 without measured κ > 0.8
```

---

*End of SOC-3s Architecture v2*
*This document is the authoritative reference for the agent-service. Read it fully
before modifying any file in the codebase.*