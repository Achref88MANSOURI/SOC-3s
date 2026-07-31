# SOC Triage Agent — Architecture Reference

---

## 1. FULL PIPELINE

```
Security Onion (Suricata / Sigma-ElastAlert / YARA-Strelka)
        │
        │  unified alert stream
        ▼
.ds-logs-detections.alerts-so-* (Elasticsearch)
        │
        │  webhook trigger
        ▼
┌─────────────────────────────────────────────────────┐
│  n8n — INGESTION LAYER (deterministic, no LLM)      │
│                                                     │
│  1. Webhook trigger                                 │
│  2. Alert builder (Python)                          │
│     • parse raw SO/Elastic JSON                     │
│     • build TheHive alert body + observables        │
│     • assign investigation_profile                  │
│     • build canonical_alert{}                       │
│  3. create alert (TheHive POST)                     │
│  4. get observable IDs (TheHive query)              │
│  5. HTTP POST → agent-service:5000/triage           │
│     body: canonical_alert{}                         │
│     waits for: triage_result{}                      │
│  6. Switch on triage_result.action:                 │
│     ├── create_case   → promote alert, assign owner │
│     ├── close_fp      → update status, log reason   │
│     ├── merge_quiet   → add to case, notify owner   │
│     ├── merge_retier  → add to case, UPDATE severity│
│     │                   URGENT notify, retier SLA   │
│     ├── needs_review  → flag for analyst            │
│     └── deduplicated  → log only, stop              │
│  7. audit ledger write (all paths)                  │
│  8. FP counter check → detection-tuning ticket      │
│     if same rule.uuid FP'd > N times in M days      │
└─────────────────────────────────────────────────────┘
        │
        │  HTTP POST /triage
        ▼
┌─────────────────────────────────────────────────────┐
│  AGENT SERVICE (FastAPI + LangGraph)                │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │ NODE 1 — CORRELATE (pure Python, no LLM)     │   │
│  │                                              │   │
│  │  check 1: Redis fingerprint dedup            │   │
│  │    key = hash(rule_uuid+src+dst+user)        │   │
│  │    window = 5 min                            │   │
│  │    hit → return {action: deduplicated}       │   │
│  │                                              │   │
│  │  check 2: entity match (TheHive API)         │   │
│  │    open cases sharing host/user/observable   │   │
│  │    hit → mode=merge, load case context       │   │
│  │                                              │   │
│  │  check 3: story match (MITRE adjacency)      │   │
│  │    kill-chain progression on related host    │   │
│  │    starts inert, improves as cases accumulate│   │
│  │    hit → mode=merge, reason=kill_chain       │   │
│  │                                              │   │
│  │  no match → mode=new                        │   │
│  └──────────────────┬───────────────────────────┘   │
│                     │                               │
│         ┌───────────┴──────────┐                   │
│       mode=new            mode=merge               │
│         │                      │                   │
│  ┌──────▼──────────────────────▼──────────────┐    │
│  │ NODE 2 — INVESTIGATE (Agent 1, ReAct+tools) │    │
│  │                                             │    │
│  │  mode=new:   full investigation             │    │
│  │              max 8 tool calls               │    │
│  │              output: evidence_package{}     │    │
│  │                                             │    │
│  │  mode=merge: delta only                     │    │
│  │              receives existing_case_context │    │
│  │              investigates only what's new   │    │
│  │              max 5 tool calls               │    │
│  │              output: delta_evidence{}       │    │
│  │                                             │    │
│  │  tools available (all read-only):           │    │
│  │    cortex_analyze                           │    │
│  │    itop_asset_lookup                        │    │
│  │    elasticsearch_query                      │    │
│  │    thehive_search                           │    │
│  │    sigma_rule_lookup                        │    │
│  │    qdrant_retrieve                          │    │
│  └──────────────────┬──────────────────────────┘   │
│                     │                               │
│  ┌──────────────────▼──────────────────────────┐   │
│  │ NODE 3 — ANALYZE (Agent 2, single LLM call) │   │
│  │                                             │   │
│  │  no tools — pure reasoning only             │   │
│  │  input: evidence_package or delta_evidence  │   │
│  │  never sees raw logs or raw API responses   │   │
│  │                                             │   │
│  │  mode=new output:                           │   │
│  │    likelihood + impact_if_true              │   │
│  │    verdict, mitre_mapping[]                 │   │
│  │    reasoning (evidence-cited)               │   │
│  │    recommended_action, summary              │   │
│  │                                             │   │
│  │  mode=merge output:                         │   │
│  │    severity_change, new_mitre_stages        │   │
│  │    scope_change, urgency                    │   │
│  │    recommended_action, reasoning            │   │
│  └──────────────────┬──────────────────────────┘   │
│                     │                               │
│  ┌──────────────────▼──────────────────────────┐   │
│  │ NODE 4 — FORMAT_OUTPUT (pure Python)        │   │
│  │                                             │   │
│  │  apply severity lookup table:               │   │
│  │    likelihood × impact_if_true → severity   │   │
│  │  build final triage_result{}                │   │
│  │  return to n8n                              │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
        │
        │  triage_result{}
        ▼
back to n8n → case actions (step 6 above)
```

---

## 2. SEVERITY LOOKUP TABLE

```
                  minor    moderate   severe    critical
unlikely          low      low        medium    medium
possible          low      medium     high      high
likely            medium   high       high      critical
near_certain      medium   high       critical  critical
```

Model produces `likelihood` + `impact_if_true`.
Severity is computed in Node 4 from this table — never a free model output.

---

## 3. AGENT 1 — INVESTIGATOR

```
MISSION
  Replicate what a senior SOC analyst does before making a call.
  Gather ALL evidence needed to assess this specific alert.
  Adapt investigation strategy based on alert type and intermediate findings.
  Mark gaps explicitly — never fill missing evidence with assumptions.

MODE A — new alert
  INPUT:  canonical_alert{}
  BUDGET: max 8 tool calls
  OUTPUT: evidence_package{}
  FOCUS:  build complete picture from scratch

  evidence_package{} contains:
    rule_context:      description, detection_logic, known_fp_conditions,
                       mitre_tags_from_source, severity_from_source
    asset_context:     hostname, criticality, owner, department,
                       services, network_zone
    threat_intel:      per-observable verdict, score, campaign_links
    temporal_context:  related_alerts_same_host_24h,
                       related_alerts_same_user_24h,
                       related_alerts_shared_iocs,
                       behavioral_baseline_deviation
    historical_context: similar_past_cases (verdict, similarity),
                        mitre_candidates_from_rag
    investigation_gaps: fields not retrieved (budget or unavailability)
    investigation_trace: tool call log (tool, params, result summary)

MODE B — merge candidate
  INPUT:  canonical_alert{} + existing_case_context{}
  BUDGET: max 5 tool calls
  OUTPUT: delta_evidence{}
  FOCUS:  what does this NEW alert add to the existing case?
          new IOCs? new host/user? new kill-chain stage?
          changed TI verdict? do NOT re-query what case already has.

INVESTIGATION PROFILES (guides tool selection, does not restrict)

  network_threat (Suricata):
    use:    cortex (IPs/domains), itop (asset), elasticsearch (related connections)
    avoid:  process ancestry, command_line, user auth queries

  endpoint_behavior (Sigma + process fields):
    use:    sigma_rule_lookup (FP, MITRE tags), elasticsearch (process/user history),
            cortex (hash), itop (asset)
    avoid:  network flow queries

  malicious_file (YARA/Strelka):
    use:    cortex (all hash types), elasticsearch (Zeek session origin, other hosts),
            itop (receiving host)
    avoid:  process ancestry, user auth

  network_anomaly (Sigma + network fields):
    use:    sigma_rule_lookup, cortex (IPs/domains), itop (asset)

  log_anomaly (Sigma, no process, no network):
    use:    sigma_rule_lookup, elasticsearch (user/entity history, alert patterns),
            itop (asset)

TOOL CALL DISCIPLINE
  - Call the cheapest/fastest tools first (sigma_rule_lookup, itop)
  - Use intermediate findings to decide next call
  - If profile says "avoid X" but evidence points to X, still call it
  - Stop early if verdict is already clear (e.g. confirmed FP from rule logic)
  - Remaining budget at early stop → mark unused, do not waste calls
```

---

## 4. AGENT 2 — ANALYST

```
MISSION
  Receive Agent 1's structured evidence. Make the call.
  Reason like a senior analyst. Show your work.
  Never invent evidence. Never fill gaps with assumptions.

CONSTRAINTS
  - No tools. No external queries. Pure reasoning only.
  - Never sees raw logs, raw API responses, or attacker-controlled strings.
    (Agent 1 summarized everything into typed fields — this is the
     prompt injection firewall)
  - Output is grammar-constrained (GBNF) — valid JSON guaranteed by
    inference server, not by hope.

MODE A — new alert
  INPUT:  evidence_package{}
  OUTPUT: triage_verdict{}

  REASONING STRUCTURE:
    step 1 — assess likelihood (grounded in evidence):
      unlikely | possible | likely | near_certain
      basis: TI verdicts, rule FP match, behavioral context,
             temporal clustering, historical cases

    step 2 — assess impact_if_true (grounded in asset + technique):
      minor | moderate | severe | critical
      basis: asset criticality, technique severity,
             scope of affected systems, data sensitivity

    step 3 — MITRE mapping:
      [{tactic, technique, sub_technique|null, confidence, basis}]
      confidence capped at evidence quality
      sub_technique only when evidence specifically supports it
      if rule source had tags → use as primary, note basis
      if RAG-derived → note it's inferred, lower confidence

    step 4 — verdict:
      true_positive | false_positive | needs_review

    step 5 — reasoning string:
      every claim cites a specific field from evidence_package
      e.g. "asset_context.criticality=high drove impact assessment"
           "threat_intel.hash_verdict.malicious=false reduced likelihood"

    step 6 — recommended_action:
      create_case | close_fp | needs_review

    step 7 — summary:
      3-5 sentences, analyst-readable, no jargon inflation

MODE B — merge candidate
  INPUT:  existing_case_context{} + delta_evidence{}
  OUTPUT: delta_verdict{}

  SINGLE QUESTION: does this new evidence materially change the case?
    severity_change:    "medium → high" | "no_change"
    new_mitre_stages:   [] | [{tactic, technique}]
    scope_change:       "1 host → 3 hosts" | "no_change"
    urgency:            escalate | routine_merge
    recommended_action: merge_and_retier | merge_quiet
    reasoning:          cite delta_evidence fields specifically

QUALITY BAR
  A verdict is only as good as the evidence it cites.
  If evidence_package has gaps, confidence must reflect that.
  "I don't know" expressed as needs_review is correct.
  Overconfident verdicts on incomplete evidence are the failure mode.
```

---

## 5. FILE LAYOUT

```
agent-service/
│
├── main.py
│     FastAPI app
│     POST /triage → receives canonical_alert{}, returns triage_result{}
│     GET  /health → liveness check
│
├── graph.py
│     LangGraph StateGraph definition
│     nodes: correlate → investigate → analyze → format_output
│     conditional edges:
│       after correlate: exact_dup → format_output (skip agents)
│                        merge/new → investigate
│     state schema: TriageState (typed dict)
│
├── config.py
│     load all env vars via python-dotenv
│     expose as typed config object
│     single import for all other modules
│
├── nodes/
│   ├── correlate.py
│   │     Redis fingerprint check (check 1)
│   │     TheHive open-case entity match (check 2)
│   │     MITRE-adjacent story match (check 3)
│   │     returns: correlation_result, mode, existing_case_context
│   │
│   ├── investigate.py
│   │     LangGraph create_react_agent
│   │     registers all tools from tools/
│   │     loads system prompt from prompts/investigator.py
│   │     mode-aware: new (max 8) / merge (max 5) tool calls
│   │     returns: evidence_package or delta_evidence
│   │
│   ├── analyze.py
│   │     single LLM call (no tool use)
│   │     loads system prompt from prompts/analyst.py
│   │     GBNF grammar enforces output schema
│   │     mode-aware: new → triage_verdict / merge → delta_verdict
│   │     returns: triage_verdict or delta_verdict
│   │
│   └── format_output.py
│         applies severity lookup table
│         builds final triage_result{}
│         handles deduplicated path (no agent output to process)
│
├── tools/
│   ├── cortex.py          ← DONE
│   │     analyze_observable(type, value) → structured verdict
│   │     handles: analyzer selection, polling, timeout, errors
│   │
│   ├── itop.py
│   │     lookup_asset(hostname_or_ip) → asset context dict
│   │     returns: criticality, owner, dept, services, network_zone
│   │
│   ├── elasticsearch.py
│   │     query_related_alerts(host, user, iocs, window) → list
│   │     query_process_history(host, user, window) → list
│   │     query_connection_history(src_ip, dst_ip, window) → list
│   │     all queries scoped read-only, return summaries not raw docs
│   │
│   ├── thehive.py
│   │     search_open_cases(observables, host, user) → list
│   │     search_closed_cases(rule_uuid, observables) → list
│   │     get_case_full(case_id) → full case context dict
│   │
│   ├── sigma_rules.py
│   │     get_rule_source(rule_uuid) → dict
│   │     returns: description, falsepositives[], tags[attack.txxxx],
│   │              level, detection logic
│   │     reads from: /opt/so/rules/sigma/ (filesystem)
│   │
│   └── qdrant.py
│         retrieve_mitre(query_text, top_k) → technique candidates
│         retrieve_playbooks(query_text, top_k) → playbook chunks
│         retrieve_cve(query_text, top_k) → CVE matches
│         embedding: bge-large-en
│
├── prompts/
│   ├── investigator.py
│   │     BASE_PROMPT: mission, constraints, output format
│   │     PROFILE_BLOCKS: dict keyed by investigation_profile
│   │     build_prompt(profile, mode) → final system prompt string
│   │
│   └── analyst.py
│         BASE_PROMPT: mission, reasoning structure, constraints
│         OUTPUT_SCHEMA: JSON schema description
│         GBNF_GRAMMAR: grammar string for inference server
│         build_prompt(mode) → final system prompt string
│
├── schemas/
│   └── models.py
│         Pydantic models for:
│           CanonicalAlert, Rule, Host, User, Network,
│           Process, File, Observables
│           EvidencePackage, DeltaEvidence
│           TriageVerdict, DeltaVerdict
│           TriageResult, CorrelationResult
│           TriageState (LangGraph state)
│
└── .env
      CORTEX_URL, CORTEX_API_KEY
      THEHIVE_URL, THEHIVE_API_KEY
      ITOP_URL, ITOP_USER, ITOP_KEY
      ES_URL, ES_API_KEY
      LLM_BASE_URL, LLM_MODEL
      QDRANT_URL
      REDIS_URL
      SIGMA_RULES_PATH
      MAX_TOOL_CALLS_NEW=8
      MAX_TOOL_CALLS_MERGE=5
      DEDUP_WINDOW_SECONDS=300
```

---

## 6. BUILD ORDER

```
PHASE 1 — tools (no LLM dependency, test each standalone)
  cortex.py          DONE
  itop.py            next
  thehive.py
  elasticsearch.py
  sigma_rules.py
  qdrant.py

PHASE 2 — schemas
  models.py          all Pydantic models

PHASE 3 — correlation (no LLM)
  nodes/correlate.py
  test: 20 real alerts, verify dedup/merge/new decisions

PHASE 4 — Agent 1
  prompts/investigator.py
  nodes/investigate.py
  test: 10 real alerts, inspect evidence_package quality manually

PHASE 5 — Agent 2
  prompts/analyst.py
  nodes/analyze.py
  test: feed phase 4 evidence_packages, compare verdicts to own judgment

PHASE 6 — graph + API
  nodes/format_output.py
  graph.py
  main.py
  end-to-end test: real alert in → triage_result out

PHASE 7 — Qdrant corpus
  ingest MITRE ATT&CK (technique + sub-technique + tactic metadata)
  ingest CVE database
  ingest playbooks / closed cases
  test retrieval quality

PHASE 8 — n8n integration
  add canonical_alert builder node (after get observable id)
  add HTTP request node (POST to agent-service)
  add Switch on triage_result.action
  add case-action branches
  remove old: Switch1, hash/url/domain/ip analyzer nodes, assets context
  keep: Webhook, Alert builder, create alert, get observable id

PHASE 9 — Tier 0 (advisory only)
  every verdict annotates the case, nothing auto-acts
  analyst reviews all decisions
  track agreement rate (Cohen's κ)
  do not move to Tier 1 without measured κ > 0.8
```