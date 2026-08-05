# SOC-3s Agent Service — Change Log
Last updated: 2026-08-05

## Phases completed
- [x] Phase 1 — Bug fixes (already resolved by a prior uncommitted session — see below)
- [x] Phase 2 — New input contract
- [x] Phase 3 — Agent 1 (perceive.py)
- [x] Phase 4 — Cortex integration (attempted via cortex-mcp, reverted to direct REST — see below)
- [x] Phase 5 — Agent 2 structured output
- [x] Phase 6 — Agent 3 two-pass MITRE
- [x] Phase 7 — Format output fixes + end-to-end (verification only — nothing was broken)
- [x] Phase 8 — Case action stub
- [x] Phase 9 — n8n integration notes
- [x] Phase 10 — Test cleanup and final validation

## Phase 1 — status at session start (no code changes needed)

Read the codebase in full against `SOC-3s-ARCHITECTURE-v2.md` §18 before writing
anything. Found that a prior, uncommitted session had already resolved 6 of the 8
listed bugs and the 7th never applied to the current code shape:

| # | §18 bug | Status found |
|---|---|---|
| 1 | Redis crashes at import if `REDIS_URL` unset | Already fixed — `correlate.py::_check_dedup` no-ops when `REDIS_URL` is falsy |
| 2 | `ExistingCaseContext` imported but missing from `schemas.py` | Not applicable — current code uses a plain `dict`, never imports that name |
| 3 | `CorrelationResult` has no `deduplicated` field but it's set | Not applicable — `action="deduplicated"` used consistently, no boolean field exists |
| 4 | `format_output.py` checks `correlation.deduplicated` | Already fixed — checks `corr.action == "deduplicated"` |
| 5 | `Impact`/`Likelihood`/`Severity` Literal aliases missing | Still missing from `schemas.py`, but nothing imports them — dead requirement |
| 6 | `ToolCallLogEntry` vs `InvestigationTraceEntry` mismatch | Not applicable — code uses `InvestigationTraceEntry` consistently everywhere |
| 7 | Agent output dumped into `rule_context["agent_notes"]` | Not applicable — `investigate.py::_build_from_tool_results` already buckets tool results into typed fields |
| 8 | `.env` has `LLM_MODEL=llama3.2:3b`, should be `qwen3:30b-a3b` | **Real, still open** — see "Questions pending" below |

71/71 tests passed before any Phase 2 work started. No Phase 1 code changes were made.

## Phase 4 — built, then reverted (cortex-mcp)

Phase 4 was implemented in full (`tools/cortex_mcp.py`, 3 tools wired into
`nodes/investigate.py` via `tools/registry.py`, prompt updates, 14 tests, 93/93
green) against a stdio-transport MCP server. The user then reported a hard
infrastructure finding: `cortex-mcp` hardcodes `StdioServerTransport` (no HTTP/SSE
mode), and `agent-service` runs on 172.20.24.224 while `cortex-mcp` is installed
on 172.20.24.221 — stdio transport requires spawning the server as a **local**
child process, which cannot cross that VM boundary. This isn't a configuration
problem; it's a hard incompatibility between the deployed topology and the only
transport `cortex-mcp` supports.

Reverted in full: deleted `tools/cortex_mcp.py` and `tests/test_cortex_mcp.py`,
restored `tools/registry.py`/`prompts/investigator.py` to their pre-Phase-4
state (`cortex_analyze` as the sole, direct-REST Cortex tool), removed the
`CORTEX_MCP_*` settings from `config.py`, removed `langchain-mcp-adapters`/`mcp<2.0`
from `requirements.txt` and uninstalled them from the environment.
`SOC-3s-ARCHITECTURE-v2.md` updated throughout (§7, §11, §14, §15, §17 Decision 2,
§19 Phase 4) to document the revert and root cause rather than presenting
cortex-mcp as live or planned — this is the kind of finding worth keeping visible
in the architecture doc, not just this log, so a future session doesn't
re-attempt the same integration without knowing why it failed.

Net effect: Agent 2's selective-invocation goal (only analyze new/high-value
observables, skip common infrastructure, don't re-analyze what TheHive already
has) is unchanged — it's just implemented via `cortex_analyze` direct REST calls
instead of an MCP layer. Test count returned to 79 (the Phase 3 baseline).

## Files modified
| File | Change summary | Phase |
|------|---------------|-------|
| schemas.py | Added `CortexResult.` moved above `CanonicalAlert` (forward-ref ordering); added `cortex_results: list[CortexResult]` and `asset_context: dict` to `CanonicalAlert`; added `imphash` field to `HashBundle` | 2 |
| main.py | Replaced local `TriageRequest(canonical_alert=...)` contract with `AlertWebhookPayload`; `/triage` now calls `tools.thehive.get_full_alert_with_analysis()` then `alert_builder.build_canonical_alert()` before invoking the graph | 2 |
| SOC-3s-ARCHITECTURE-v2.md | §11 and §14 corrected: TheHive access is raw `requests` (not `thehive4py`), verified against live 5.6.1; Qdrant embedding is `BAAI/bge-m3` via raw `sentence-transformers` in one `triage_kb` collection with a `collection` discriminator (not `fastembed` + 3 collections). User confirmed: code wins, doc updated to match. | 2 |
| graph.py | Replaced the single `correlate` node with `gate0` (dedup, pure Python) → `perceive` (Agent 1, LLM), per §13's shape. Routing: `gate0` → `format_output` on dedup hit, else `perceive`; `perceive` → `format_output` on dedup, else `investigate`. | 3 |
| tests/test_graph.py | Rewrote route tests for `_route_after_gate0`/`_route_after_perceive` (was `_route_after_correlate`); `test_graph_nodes` now checks for `gate0`/`perceive` instead of `correlate` | 3 |
| prompts/investigator.py | Net change after Phase 4 build + revert: retained 2 discipline rules (check existing `cortex_results` before calling `cortex_analyze`; skip common infrastructure) — everything cortex-mcp-specific (3-tool sequence, submit/wait pairing) was reverted along with the tool itself. Verified via `git diff` against the pre-Phase-4 commit: this is the only file with any net difference. | 4 |
| nodes/investigate.py | Added an explicit "Existing Cortex results" block to Agent 2's human message (was only implicit via the full alert JSON dump); added `_merge_cortex_results()` so Agent 1's pre-fetched Cortex data survives into the final `EvidencePackage.threat_intel` regardless of the LLM's output, including on total agent failure; removed dead code `_gap_msg()`/`_fallback_extract()` (zero call sites); fixed a latent bug in `_to_cortex_results()`'s except-fallback path (re-used the same malformed `score` value that caused the exception, so the fallback threw the same error uncaught — added `_coerce_score()`) | 5 |
| nodes/analyze.py | `mode == "new"` branch now reads `state["mitre_mapping"]` (Agent 1's output) and includes it as `agent1_initial_mitre_mapping` in the human message, ahead of `evidence_package_summary` — targeted change, merge-mode branch untouched | 6 |
| prompts/analyst.py | Step 3 rewritten from "produce a mapping" to an explicit validate-and-refine instruction against `agent1_initial_mitre_mapping` — keep+recompute confidence if evidence confirms a technique, drop/downgrade if contradicted, add if evidence reveals something Agent 1 missed. Rest of the prompt (Steps 1-2, 4-7, MERGE_PROMPT, schemas, GBNF grammar) untouched. | 6 |
| tools/thehive.py | Added a `_thehive_patch()` helper (matching the existing `_thehive_get`/`_thehive_post` style) and 6 write functions for `nodes/case_action.py`: `promote_alert_to_case`, `update_case`, `add_case_comment`, `update_alert_status`, `add_alert_comment`, `merge_alert_into_case`. All existing read-only functions untouched. Not registered in `tools/registry.py` — read-only invariant for the LLM agents preserved. | 8 |
| tests/test_analyze.py | Added 3 tests mocking `nodes.analyze._llm` — first LLM-in-the-loop test coverage for this module (previously only pure-helper tests existed): `agent1_initial_mitre_mapping` reaches the human message, the final `TriageVerdict.mitre_mapping` is Agent 3's own parsed output (not a pass-through — used deliberately different technique IDs in agent1 vs agent3 mock output to prove it), and the missing-`state["mitre_mapping"]` case degrades gracefully | 6 |

## Phase 7 — verification only, no fixes needed

Read `format_output.py` and `schemas.py` fresh per the user's explicit instruction
("verify against current code" before touching anything). Both items believed
open turned out to already be resolved:

- `format_output.py` checks `corr.action == "deduplicated"` — correct, and
  `CorrelationResult` has no boolean `deduplicated` field to confuse it with.
  This was already true as of Phase 1's initial read; re-verified here.
- §18 bug 5 (`Impact`/`Likelihood`/`Severity` Literal aliases): grepped the full
  codebase for all three names — zero imports or usages anywhere except two
  unrelated code comments in `test_perceive.py` referencing the MITRE "Impact"
  tactic. Not a live bug; did not add the aliases speculatively since nothing
  needs them.

No code changes to `format_output.py` or `schemas.py` this phase — per the
user's instruction to fix only what's actually broken.

## Phase 8 — case action stub, unwired by design

`nodes/case_action.py` is intentionally **not** imported by `graph.py` or
`main.py` — verified with `grep` after implementation. n8n still performs case
actions today; this is the future post-approval path. The write functions added
to `tools/thehive.py` are also **not** added to `tools/registry.py`'s `TOOLS` —
verified the list is unchanged (still the same 6 read-only tools) so the LLM
agents never gain write access.

**Caveat carried forward, not resolved this phase:** the new `tools/thehive.py`
write functions (`promote_alert_to_case`, `update_case`, `add_case_comment`,
`update_alert_status`, `add_alert_comment`, `merge_alert_into_case`) are
implemented against TheHive 5's documented v1 REST API shape, but — unlike
`get_full_alert_with_analysis()` — have not been verified against the live
5.6.1 instance from this environment (no live TheHive reachable here, and this
code isn't wired into anything that would exercise it against production).
Confirm the exact endpoint paths against the live Swagger UI before wiring
this into a real approval flow. **Update:** the alert `status` enum question
specifically was resolved the same session — see below.

## Phase 9 — n8n integration documentation

n8n isn't part of this repo (`CLAUDE.md`: "n8n POSTs a normalized canonical_alert
to /triage" — it's the ingestion layer, lives elsewhere). Phase 9's deliverable
is therefore a document, not code: `N8N-INTEGRATION.md`, written for whoever
maintains the actual n8n workflow. Nothing in it was applied to a live n8n
instance — there's no n8n reachable from this session to apply or test against.

Covers: the new slim `/triage` request contract (with the exact `raw_alert`
shape restated from `SOC-3s-ARCHITECTURE-v2.md` §3), which n8n nodes to remove
(the Cortex Switch/analyzer nodes, the observable-ID fetch step — both now
redundant since Agent 2 calls Cortex itself and `get_full_alert_with_analysis()`
fetches observables itself), the `TriageResult` response shape and action
routing table (including the "Ignored" not "FP" fix), and an explicit callout
that `nodes/case_action.py` is **not** wired into the graph — n8n still
performs the actual TheHive writes today, exactly as before this migration.
Also notes that if n8n's existing case-action HTTP nodes already work in
production, they're a more trustworthy source of truth for exact TheHive
endpoint shapes than `tools/thehive.py`'s new (unverified) write functions.

### Follow-up fix: close_fp uses "Ignored", not "FP"

User verified against the live TheHive 5.6.1 instance's UI: no custom alert
statuses are configured, only the built-in `New`/`Updated`/`Ignored`/`Imported`.
`"FP"` is not a valid value. Fixed `nodes/case_action.py::_close_fp()` to pass
`"Ignored"` (TheHive's built-in status for false positive / not actionable
alerts) with a comment explaining why, and updated
`test_close_fp_updates_status_and_comments` in `tests/test_case_action.py` to
assert `"Ignored"`. One-line fix + one test assertion, as scoped. Also updated
`SOC-3s-ARCHITECTURE-v2.md` (§2 pipeline diagram, §10 action routing table,
§19 Phase 8 entry) to say `"Ignored"` instead of `"FP"` throughout.

## Phase 10 — test coverage audit and final validation

No code changed this phase — audit and documentation only, per explicit
instruction not to pad the test count with speculative tests.

**112/112 tests passing**, confirmed via `python3 -m pytest tests/ -q`.

### Coverage audit — `nodes/`, `tools/`, `prompts/`

`nodes/` — every module has a dedicated test file: `analyze.py`, `case_action.py`,
`format_output.py`, `investigate.py`, `perceive.py` all covered.

`tools/` — **zero dedicated test coverage:**
- `tools/cortex.py` (`analyze_observable`, analyzer selection, taxonomy
  reduction) — nothing exercises this file directly. It's the sole live Cortex
  path for Agent 2 as of the Phase 4 revert, and has no test of its own.
- `tools/elasticsearch.py` (`query_related_alerts`, `query_process_history`,
  `query_connection_history`) — untested.
- `tools/itop.py` (`lookup_asset`) — untested.
- `tools/registry.py` (all `@tool`-wrapped functions: `cortex_analyze`,
  `itop_asset_lookup`, `elasticsearch_query`, `thehive_search`,
  `sigma_rule_lookup`, `qdrant_retrieve`, plus the `PERCEPTION_TOOLS` wrappers)
  — untested. This is the module the ReAct agents actually call; its
  parameter-parsing logic (e.g. `elasticsearch_query`'s `index_type` dispatch,
  comma-separated list parsing in `thehive_search`/`thehive_open_cases`) has no
  test of its own, only indirect coverage via mocked-away ReAct agents
  elsewhere.
- `tools/sigma_rules.py` (`get_rule_source`, filesystem walk + YAML parsing) —
  untested.

`tools/` — **partial coverage:**
- `tools/thehive.py` — `test_thehive.py` only covers
  `get_full_alert_with_analysis` (4 tests). `search_open_cases`,
  `search_closed_cases`, `get_case_full` (pre-existing read functions) and all
  6 Phase 8 write functions (`promote_alert_to_case`, `update_case`,
  `add_case_comment`, `update_alert_status`, `add_alert_comment`,
  `merge_alert_into_case`) have no direct test — the write functions are only
  exercised indirectly by `test_case_action.py`, which mocks them at the
  `nodes.case_action` import boundary and therefore never executes their
  actual HTTP-request-building logic.
- `tools/qdrant.py` — fully covered (`test_qdrant.py`, 4 tests: all three
  retrieve functions + exception handling).

`prompts/` — **zero coverage:**
- `prompts/perceiver.py` — `build_prompt()` has no test at all. `test_prompts.py`
  only imports from `prompts.investigator` and `prompts.analyst`.

`prompts/` — covered: `prompts/analyst.py`, `prompts/investigator.py` (both via
`test_prompts.py`).

**Outside the audited directories, for completeness:** `main.py` and `graph.py`
have no dedicated unit test file but are exercised end-to-end by
`test_e2e.py`'s 2 `TestClient`-based tests. `config.py` has no test file
(low-risk — pure env-var loading with defaults). `alert_builder.py` is fully
covered by `test_alert_builder.py`.

Per the explicit instruction for this phase, none of these gaps were filled —
they're recorded as known issues below, not closed.

### Architecture doc drift audit

Read `SOC-3s-ARCHITECTURE-v2.md` fresh against the current codebase, focused on
sections not already touched by earlier phases' corrections (TheHive/Qdrant/
cortex-mcp/case-action sections were kept in sync as each phase landed — see
their respective sections above). Found drift in two sections that were never
revisited after the initial pre-work draft:

1. **§12 (Schemas) has fallen substantially out of sync with `schemas.py`.**
   Specific mismatches: `TriageRequest` (legacy model) is documented but
   doesn't exist in code; `Rule.uuid`/`Rule.source_engine` don't match
   (`uuid` is required not Optional in code, no `source_engine` field on
   `Rule` — it lives on `CanonicalAlert` instead); `Host.hostname` is
   `Optional` in code but shown required in the doc; `CortexResult.score` is
   `int` in code, `float` in the doc; `CanonicalAlert.host`/`.user` are
   `Optional` in code but shown required; `thehive_observable_ids` is a `dict`
   in code but a `list[str]` in the doc; **`ExistingCaseContext` doesn't exist
   in code at all** (this was flagged back in the very first session read —
   `CorrelationResult.existing_case_context` is a plain `dict`, not a typed
   model); `CorrelationResult` is missing `merge_into_case` from the doc
   entirely (a field the real code depends on throughout `format_output.py`)
   and has no `deduplicated` field in code (the doc marks it "DEPRECATED" as
   if it still exists); **`ToolCallLogEntry` alias doesn't exist** (§18 bug 6,
   confirmed not applicable back in the Phase 1 read, but the doc still shows
   it); `EvidencePackage.threat_intel` is `list[CortexResult]` in code, shown
   as `list[dict]`; **`Impact`/`Likelihood`/`Severity` Literal aliases don't
   exist anywhere** (§18 bug 5, confirmed again in Phase 7); **`TriageState`
   has no `perception_result` field** — the doc shows Agent 1's output bundled
   into a single `PerceptionResult` object, but the real state shape is flat
   (`mitre_mapping` and `correlation_result` as separate top-level keys,
   plus `raw_alert`/`asset_context`/`thehive_alert_id` for the webhook path,
   none of which are in the doc's `TriageState`). Related: `PerceptionResult`
   *is* defined in `schemas.py` but is dead code — nothing constructs or
   references it anywhere; `nodes/perceive.py` writes the flat state fields
   directly instead.
2. **§15 (File Tree) reads as the original pre-work TODO list and was never
   updated as phases completed** — unlike §19 (Build Order), which was updated
   after every phase in this session. Example: `prompts/perceiver.py`'s entry
   still says `build_prompt(mode)`, which was already known-inconsistent with
   Agent 1's actual role and built as `build_prompt()` instead back in Phase 3
   (see `CHANGES.md`'s Phase 3 section) — §15 was never corrected to match.
   The `tests/` section similarly doesn't list `test_investigate.py`,
   `test_case_action.py`, `test_e2e.py`, or the deleted `test_cortex_mcp.py`.
   **§19 is the current source of truth for phase status; §15 is stale
   throughout and shouldn't be trusted for "what's done."**

Per the explicit instruction for this phase, `SOC-3s-ARCHITECTURE-v2.md` was
**not** rewritten to fix these — they're listed here as findings only.

## Files created
| File | Purpose | Phase |
|------|---------|-------|
| alert_builder.py | `build_canonical_alert(raw_alert, hive_alert, asset_context, thehive_alert_id)` — deterministic, best-effort CanonicalAlert assembly from n8n's slim payload + TheHive fetch + iTop context. Includes the mandatory observable dataType sanity check (URL mis-tagged as domain). Fields it can't confidently parse (user, network, most file/process cases) are left `None` — that's intentional, Agent 1 (Phase 3) fills gaps with LLM reasoning. | 2 |
| tests/test_alert_builder.py | 5 tests: rule/host/process parsing from description text, URL-mis-tagged-as-domain correction, Cortex report mapping from TheHive fetch, missing-hive_alert handling, fallback behavior when description has no structured fields | 2 |
| prompts/perceiver.py | `build_prompt()` — Agent 1's system prompt: MITRE mapping + case correlation reasoning (entity match strength, kill-chain progression), 3-tool budget-4 ReAct loop, `{mitre_mapping, correlation_result}` JSON output contract. No `mode` parameter — Agent 1 *decides* mode, it doesn't receive it (the architecture doc's file-tree table says `build_prompt(mode)` for this file, but that's inconsistent with Agent 1's actual role per §6; built as `build_prompt()` instead). | 3 |
| nodes/perceive.py | Replaces `nodes/correlate.py`. `gate0_dedup()` — pure Python Redis fingerprint check, ported verbatim from `correlate.py`. `perceive()` — Agent 1: a `create_react_agent` ReAct loop over `PERCEPTION_TOOLS` (`sigma_rule_lookup`, `qdrant_retrieve_mitre`, `thehive_open_cases`) producing `mitre_mapping` + `correlation_result`. On agent exception or unparseable JSON, falls back to `_fallback_deterministic()` — the same entity-match/kill-chain logic `correlate.py` used (ported, not imported, since `correlate.py` is retired), minus MITRE mapping (an empty list + a "fallback" reason is the safe degraded state, not a guess). Preserves the "every LLM-facing node has a non-LLM fallback" invariant. | 3 |
| tests/test_perceive.py | 15 tests: ported kill-chain/tactic-index unit tests from `test_correlate.py`; `gate0_dedup` duplicate/no-duplicate/no-alert cases; `perceive()` with a mocked `create_react_agent` for new-mode and merge-mode JSON parsing, unparseable-JSON fallback, agent-`.invoke()`-exception fallback (mocking `.invoke()` to raise, not `create_react_agent()` itself — construction isn't try/except-wrapped, matching `investigate.py`'s existing pattern), already-deduplicated short-circuit, and missing-alert no-op | 3 |
| tests/test_investigate.py | 17 tests, first-ever coverage for `investigate.py`: `_try_parse_json` edge cases, `_to_cortex_results` (including the malformed-score fallback bug found and fixed in this phase), `_merge_cortex_results` dedup behavior, `_build_from_tool_results` bucketing, `_extract_trace` call/result pairing, `_get_final_text`, and `investigate()` end-to-end for new-mode JSON parse, merge-mode JSON parse, unparseable-JSON fallback, existing-cortex-results survival through both the normal and agent-exception paths, and no-alert no-op | 5 |

| tests/test_e2e.py | 2 tests via FastAPI's `TestClient` against the real `/triage` route (not `graph.invoke()` directly — exercises `main.py`'s wiring too): a full new-mode run using `alert-sample.json`'s raw Security Onion webhook body converted into the actual `AlertWebhookPayload.raw_alert` shape n8n sends, with all 6 external dependencies mocked (TheHive fetch, Agent 1/2 ReAct-loop LLM calls, Agent 3's direct LLM call — Qdrant/ES/iTop/Cortex only reachable through the mocked ReAct loops), asserting 200 + a well-formed `TriageResult`; and a deduplicated-result routing test asserting `investigate`'s agent is never constructed when `perceive` reports `action=deduplicated` | 7 |
| nodes/case_action.py | `execute_case_action(triage_result, approved) -> dict` — the post-approval TheHive write path (stub, not wired into `graph.py`). Raises `ValueError` immediately if `approved` is `False`. 4 branches on `triage_result.action`: `create_case`/`close_fp`/`merge_quiet`/`merge_and_retier` per the exact spec in §10. Unknown actions return `{"status": "skipped", ...}`. | 8 |
| tests/test_case_action.py | 11 tests mocking `tools/thehive.py`: `approved=False` raises before any TheHive call (both a bare-raise check and a call-count check), all 4 action branches call the right operations with the right arguments (including severity string→int mapping and MITRE-tag construction for `create_case`), missing `merge_into_case` on both merge branches returns a clean error dict instead of calling TheHive with `None`, unknown and `deduplicated` actions skip gracefully | 8 |
| N8N-INTEGRATION.md | Migration guide for whoever maintains the n8n workflow (n8n isn't in this repo) — the new slim `/triage` request contract, which n8n nodes to remove, the `TriageResult` response/routing table, the "Ignored" vs "FP" fix, and an explicit callout that n8n still performs TheHive writes today since `nodes/case_action.py` isn't wired in | 9 |
| Old name | New name / action | Reason |
|----------|------------------|--------|
| nodes/correlate.py | nodes/perceive.py | Role changed from pure-Python correlation to LLM-powered perception + correlation, per architecture §17 Decision 1 |
| tests/test_correlate.py | tests/test_perceive.py | Follows the node rename; deterministic-logic tests ported over, LLM-path tests added |
| tools/cortex_mcp.py | Deleted (Phase 4, built then reverted same session) | stdio transport can't cross the agent-service (172.20.24.224) / cortex-mcp (172.20.24.221) VM boundary — see the Phase 4 revert section above |
| tests/test_cortex_mcp.py | Deleted (Phase 4, built then reverted same session) | Tested code that no longer exists |

## Placeholders requiring configuration
None — no new external services were wired up this session.

## Questions asked to user (resolved)
| Question | Answer | Phase |
|----------|--------|-------|
| Doc vs code conflict: TheHive access (thehive4py vs raw requests) and Qdrant embedding (fastembed/bge-small vs sentence-transformers/bge-m3) | Code wins on both — doc updated, code left as-is | 2 |
| Is qwen3:30b-a3b ready on the Ollama host? | Confirmed set — `.env`'s `LLM_MODEL=qwen3:30b-a3b` (verified via `python3 -c "import config; print(config.LLM_MODEL)"`) | — |
| Create `requirements-dev.txt` now? | No, leave for later | — |
| TheHive version | Confirmed 5.6.1 (already verified in `tools/thehive.py`'s docstring from a prior session) | — |
| How to proceed given Phase 1 was already resolved | Start Phase 2 | 2 |
| cortex-mcp deployment | Installed and tested at `/opt/cortex-mcp/dist/index.js` on 172.20.24.221, stdio transport. `.env` now has `CORTEX_MCP_COMMAND=node`, `CORTEX_MCP_ARGS=/opt/cortex-mcp/dist/index.js`, `CORTEX_MCP_CORTEX_URL=http://172.20.24.221:9001` (per user — NOT actually present in the real `.env` yet as of Phase 4, see Known issues) | — (Phase 4 prep) |
| Proceed to Phase 3 | Yes — start `perceive.py` | 3 |
| cortex-mcp source review | Confirmed clean: auth from env vars only (never logged), no observable data written to console/disk, graceful top-level catch on failure, no filesystem writes anywhere in the source | 4 |
| cortex-mcp tool spec | User provided exact tool names/schemas from source (analyzers.ts, jobs.ts): `cortex_list_analyzers(dataType?)`, `cortex_run_analyzer_by_name(analyzerName, dataType, data, tlp=2, pap=2)` → `{jobId, analyzerUsed}`, `cortex_wait_and_get_report(jobId, timeout?)`. Explicitly do NOT collapse into a single `analyze_observable()` wrapper — the two-step submit/wait pattern must be explicit tool calls so Agent 2 can reason about which observables to skip before committing budget. Skip `cortex_run_analyzer` (needs analyzer ID not name), `cortex_get_job`, `cortex_get_job_report`, `cortex_run_analyzer_file` — not needed. | 4 |
| Normalization gap (perceive.py doesn't re-run LLM normalization on CanonicalAlert fields, §6 sub-task 2) | Option A — accept for now, document as known gap | 3 |
| Where does agent-service run relative to 172.20.24.221 (stdio transport needs to spawn `node` as a local child process, which only works if agent-service runs on the same host)? | Answered by the user's own follow-up infrastructure finding: agent-service is on 172.20.24.224, cortex-mcp is on 172.20.24.221 — different VMs. Root cause of the Phase 4 revert (see above). | 4 |
| Proceed to Phase 4 | Yes — cortex-mcp integration into investigate.py (later reverted same session — see Phase 4 section above) | 4 |
| cortex-mcp deployment topology finding | stdio-only (`StdioServerTransport` hardcoded, no HTTP mode), agent-service (172.20.24.224) and cortex-mcp (172.20.24.221) on different VMs — stdio cannot cross that boundary | 4 (revert) |
| Revert decision | Remove `tools/cortex_mcp.py`, restore `tools/cortex.py`/direct REST as Agent 2's Cortex path, same selective-invocation behavior via Agent 2's own reasoning | 4 (revert) |
| Proceed to Phase 5 | Yes — Agent 2 structured output | 5 |
| Proceed to Phase 6 | Yes — Agent 3 two-pass MITRE validation. User specified the exact scope: nodes/analyze.py passes perception_result.mitre_mapping to Agent 3, prompts/analyst.py instructs validation against evidence, TriageVerdict.mitre_mapping must reflect Agent 3's validated mapping not a blind pass-through, targeted change only | 6 |
| Proceed to Phase 7 | Yes — format_output.py fixes + end-to-end test. User specified: verify (not assume) the deduplicated check and §18 bug 5 status against current code first, report findings, then fix only what's actually broken; e2e test must mock all external calls (TheHive, LLM, Qdrant, ES, iTop, Cortex) | 7 |
| Proceed to Phase 8 | Yes — case action stub. User specified the exact signature, the four action branches and what each must do, direct REST not TheHive MCP (citing Decision 5), that it's a stub not wired into the graph, and to read tools/thehive.py first before adding anything | 8 |
| Is "FP" a valid TheHive 5.6.1 alert status? | No — user verified against the live UI: no custom statuses configured, only built-in New/Updated/Ignored/Imported. close_fp must use "Ignored". | 8 (follow-up) |
| Proceed to Phase 9 | Yes — N8N-INTEGRATION.md documentation, no other code changes | 9 |

## Questions pending user response
| Question | Why needed | Blocking phase |
|----------|-----------|----------------|
| Has the agent-service IP been added to Security Onion's `elasticsearch_rest` firewall hostgroup? | ES queries will fail without it | Blocks live smoke testing, not blocking code phases |
| Is `SIGMA_RULES_PATH=/opt/so/rules/sigma` actually mounted/reachable from where agent-service runs? | `sigma_rule_lookup` depends on it | Blocks live smoke testing, not blocking code phases |

## Known issues / TODOs
- [ ] `requirements.txt` still lists `fastembed` though it's unused (raw `sentence-transformers` is what's actually used for Qdrant embedding) — minor cleanup, left alone per not being in scope this session.
- [ ] `requirements-dev.txt` still doesn't exist (`test.sh`'s dependency-install step will fail) — explicitly deferred by user.
- [ ] `Impact`/`Likelihood`/`Severity` Literal aliases still not in `schemas.py` (§18 bug 5) — harmless since nothing imports them, but should be added if/when something starts using them for validation.
- [x] ~~`graph.py` still calls the node `correlate`, not `perceive`~~ — done in Phase 3.
- [ ] `alert_builder.py`'s host/rule parsing is regex-over-description-text, matching the exact example format in §3. Real n8n output may vary; Agent 1 (Phase 3) is the actual normalization layer per the architecture — this deterministic pass is intentionally best-effort.
- [x] ~~cortex-mcp requires explicit source-review confirmation before Phase 4~~ — confirmed clean in Phase 4 (see Questions resolved).
- [ ] `nodes/perceive.py`'s `perceive()` doesn't re-normalize `CanonicalAlert` fields (host/user/network/process) the way architecture §6 sub-task 2 describes — it takes `alert_builder.py`'s deterministic output as given and focuses on MITRE mapping + correlation (sub-tasks 3-6). **Accepted as a known gap per user decision (Option A)** — not planned for a near-term phase.
- [ ] `test_perceive.py`'s LLM-path tests mock `create_react_agent` entirely (no real model call) — same limitation `investigate.py`/`analyze.py` already had (no LLM-in-the-loop test coverage exists anywhere in this suite). Real behavior against qwen3:30b-a3b hasn't been verified.
- [x] ~~`mcp` 2.0.0 breaks `langchain-mcp-adapters` 0.3.1~~ — moot: `mcp`/`langchain-mcp-adapters` uninstalled from the environment and removed from `requirements.txt` along with the rest of the cortex-mcp revert.
- [x] ~~cortex-mcp's `.env` vars not actually present~~ — moot: cortex-mcp integration reverted, those vars are no longer used anywhere in the code.
- [ ] `nodes/case_action.py`'s TheHive write functions (`promote_alert_to_case`, `update_case`, `add_case_comment`, `update_alert_status`, `add_alert_comment`, `merge_alert_into_case`) are implemented from TheHive 5's documented v1 REST API shape, not verified against the live 5.6.1 instance — this module is a stub, not wired into anything that would exercise it against production. Verify the exact endpoint paths against the live Swagger UI before wiring this into a real approval flow. (The alert `status` enum question specifically is resolved — `close_fp` correctly uses `"Ignored"`, verified against the live UI.)
- [ ] `nodes/case_action.py` is not wired into `graph.py`/`main.py` — intentional per Phase 8 scope, but means there's currently no code path that actually calls it outside tests. Wiring it in (behind an approval gate) is future work, not scoped to any phase yet.
- [x] ~~Whether agent-service runs on the same host as cortex-mcp~~ — resolved: it doesn't (172.20.24.224 vs 172.20.24.221), which is exactly why Phase 4 was reverted.
- [ ] **Zero test coverage:** `tools/cortex.py`, `tools/elasticsearch.py`, `tools/itop.py`, `tools/registry.py`, `prompts/perceiver.py`. See Phase 10's coverage audit above for detail. Not filled in this session per explicit instruction not to pad the test count speculatively — flagged here so the gap is visible, not silently accepted. (`tools/sigma_rules.py` was in this list at Phase 10 — it's now `tools/detection_rules.py` with 12 tests, added as a side effect of Phase B's rename+extension, not a dedicated coverage pass.)
- [ ] **Partial test coverage:** `tools/thehive.py` — only `get_full_alert_with_analysis` is directly tested; `search_open_cases`, `search_closed_cases`, `get_case_full`, and all 6 Phase 8 write functions have no direct test (the write functions are only exercised indirectly, via mocks, by `test_case_action.py`).
- [x] ~~`SOC-3s-ARCHITECTURE-v2.md` §12 (Schemas) has drifted significantly from `schemas.py`~~ — **fixed in the post-Phase-10 cleanup commit** (see below): §12 rewritten field-for-field against the actual `schemas.py`, and `PerceptionResult` (confirmed dead — referenced nowhere outside its own definition) removed from `schemas.py` itself, not just documented as gone.
- [ ] **`SOC-3s-ARCHITECTURE-v2.md` §15 (File Tree) is stale throughout** — never updated as phases completed, unlike §19. Don't use it as a source of truth for what's done; use §19 instead.
- [x] ~~`PerceptionResult` is still referenced in §6, §7, §15, and §19~~ — **swept in the "doc cleanup — PerceptionResult sweep" commit** below. `grep -rn "PerceptionResult" SOC-3s-ARCHITECTURE-v2.md` now returns zero hits (including the two explanatory sentences in §12 itself, which were rephrased to not need the literal name, per the user's literal "confirm zero hits" done-condition — not just left as accurate-but-matching text).

## Test results
| Phase | Tests run | Pass | Fail | Notes |
|-------|----------|------|------|-------|
| 1 (baseline) | `python3 -m pytest tests/ -q` | 71 | 0 | Before any code changes |
| 2 | `python3 -m pytest tests/ -q` | 76 | 0 | +5 new tests in `test_alert_builder.py`; also re-ran `test.sh`'s syntax-check and import/route-registration checks manually (no `requirements-dev.txt` yet) — both passed |
| 3 | `python3 -m pytest tests/ -q` | 79 | 0 | `test_correlate.py` (11 tests) retired, `test_perceive.py` (15 tests) added, `test_graph.py` rewritten (7 tests) — net +3. Syntax check, import check, and `graph.nodes` inspection (`gate0`, `perceive`, `investigate`, `analyze`, `format_output` all present) also passed manually. |
| 4 (build) | `python3 -m pytest tests/ -q` | 93 | 0 | +14 new tests in `test_cortex_mcp.py` (12) plus incidental coverage. `langchain-mcp-adapters` + `mcp==1.29.0` installed to make these imports/tests possible. |
| 4 (revert) | `python3 -m pytest tests/ -q` | 79 | 0 | Back to the Phase 3 count — `test_cortex_mcp.py` deleted. `git diff` against the pre-Phase-4 commit confirms `config.py`/`tools/registry.py`/`requirements.txt` are byte-identical; `prompts/investigator.py` retains 2 intentional discipline-rule lines (see Files modified). `langchain-mcp-adapters`/`mcp` uninstalled from the environment. |
| 5 | `python3 -m pytest tests/ -q` | 96 | 0 | +17 new tests in `test_investigate.py`. One test (`test_to_cortex_results_malformed_dict_falls_back`) initially failed against real (pre-existing) code, exposing the `_coerce_score` bug — fixed, then green. Syntax check and import check also passed manually. |
| 6 | `python3 -m pytest tests/ -q` | 99 | 0 | +3 new tests in `test_analyze.py`. Syntax check and import check also passed manually. |
| 7 | `python3 -m pytest tests/ -q` | 101 | 0 | +2 new tests in `test_e2e.py` (both passed on first run — no code changes needed this phase). Syntax check and import check also passed manually. |
| 8 | `python3 -m pytest tests/ -q` | 112 | 0 | +11 new tests in `test_case_action.py`. Syntax check, import check, and `tools.registry.TOOLS` listing (unchanged — still 6 read-only tools) also verified manually. Confirmed via `grep` that `case_action` is not referenced in `graph.py`/`main.py`. |
| 8 (follow-up) | `python3 -m pytest tests/ -q` | 112 | 0 | "FP" → "Ignored" fix — one line in `nodes/case_action.py`, one assertion in `tests/test_case_action.py`. Same test count, all still green. |
| 9 | `python3 -m pytest tests/ -q` | 112 | 0 | Documentation-only phase — no code changed, same test count. |
| 10 | `python3 -m pytest tests/ -q` | 112 | 0 | Audit-only phase — no code or test changed. Also ran `python3 -m pytest tests/ -v --tb=short` for the coverage audit (see Phase 10 section above). |

## Session summary

**11 commits**, spanning the initial Phase 0 read-through through Phase 10's
audit. **112 tests passing, 0 failing**, up from 71 at session start (net +41;
the actual gross additions are higher since Phase 4's 14 tests were added then
removed with the rest of that revert).

### Commits (oldest to newest)
1. `55dcc5c` — Reconcile TheHive/Qdrant tooling against verified live infra (carried forward a prior session's uncommitted work + doc corrections)
2. `017dbde` — Phase 2: accept AlertWebhookPayload, add alert_builder.py
3. `e0661a2` — Phase 3: replace correlate.py with LLM-powered perceive.py (Agent 1)
4. `f778b79` — Phase 4: cortex-mcp integration into investigate.py
5. `e7dcf9a` — Revert Phase 4: cortex-mcp is stdio-only, can't cross the agent-service/cortex-mcp VM boundary
6. `a6392b6` — Phase 5: Agent 2 structured output hardening
7. `4f9f404` — Phase 6: Agent 3 two-pass MITRE validation
8. `41c9029` — Phase 7: verify format_output.py + add end-to-end test
9. `7ee28db` — Phase 8: case action stub (execute_case_action), not wired into graph.py
10. `3fdcb7a` — Fix close_fp: use TheHive's built-in "Ignored" status, not "FP"
11. `3342c08` — Phase 9: N8N-INTEGRATION.md migration guide

*(Phase 10 itself produced no commit — audit only, this `CHANGES.md` update is
the only change and will be committed alongside this report.)*

### New files created (14, net of the Phase 4 build+revert cycle)
`SOC-3s-ARCHITECTURE-v2.md`, `CHANGES.md`, `N8N-INTEGRATION.md`,
`claude-code-session-prompt.md`, `alert_builder.py`, `nodes/case_action.py`,
`prompts/perceiver.py`, `tests/test_alert_builder.py`,
`tests/test_case_action.py`, `tests/test_e2e.py`, `tests/test_investigate.py`,
`tests/test_perceive.py`, `tests/test_qdrant.py`, `tests/test_thehive.py`.

*Also created and then fully deleted within the session (Phase 4 build +
revert, net zero against the starting commit, not in the list above):*
`tools/cortex_mcp.py`, `tests/test_cortex_mcp.py`.

### Files renamed
`nodes/correlate.py` → `nodes/perceive.py` (role changed from pure-Python
correlation to LLM-powered perception + correlation).

### Files modified (14)
`config.py`, `graph.py`, `main.py`, `nodes/analyze.py`,
`nodes/investigate.py`, `prompts/analyst.py`, `prompts/investigator.py`,
`requirements.txt`, `schemas.py`, `tests/test_analyze.py`,
`tests/test_graph.py`, `tests/test_schemas.py`, `tools/qdrant.py`,
`tools/registry.py`, `tools/thehive.py`.

### Files deleted
`CONTEXT.md`, `preview.md`, `summary.md` (superseded by
`SOC-3s-ARCHITECTURE-v2.md`), `tests/test_correlate.py` (superseded by
`tests/test_perceive.py`).

### Decisions made, with outcomes
| # | Decision point | Outcome |
|---|---|---|
| 1 | TheHive access: `thehive4py` (doc) vs raw `requests` (code) | Code wins — doc corrected to match the verified-working raw REST implementation |
| 2 | Qdrant embedding: `fastembed`+`bge-small` (doc) vs `sentence-transformers`+`bge-m3` (code) | Code wins — doc corrected; matches a prior-session empirical finding already in memory |
| 3 | `LLM_MODEL` — was `llama3.2:3b`, needed `qwen3:30b-a3b` | Confirmed already set correctly in the real `.env`; no code change needed |
| 4 | `requirements-dev.txt` missing | Deferred by user — still open |
| 5 | Whether to build `cortex-mcp` integration (Phase 4) | Built in full (3 tools, prompt updates, 14 tests) — see #7 |
| 6 | `cortex-mcp` source review requirement (architecture Rule 8) | User confirmed clean (auth handling, no logging, graceful failure, no fs writes) — cleared the way for #5 |
| 7 | `cortex-mcp` deployment topology (stdio transport, different VMs) | **Reverted** — stdio can't cross the agent-service (172.20.24.224) / cortex-mcp (172.20.24.221) VM boundary. Full revert to direct REST via `tools/cortex.py`, same selective-invocation behavior |
| 8 | `perceive.py` not re-normalizing `CanonicalAlert` fields (§6 sub-task 2) | Accepted as a known gap (Option A) — not implemented, documented instead |
| 9 | Phase 6 scope (two-pass MITRE validation) | Implemented exactly as scoped — `analyze.py` passes Agent 1's mapping, `analyst.py` instructs validation, `TriageVerdict.mitre_mapping` proven (via test) to be Agent 3's own output, not a pass-through |
| 10 | Phase 7 approach (verify-first, not rewrite) | Both suspected bugs turned out to already be non-issues; zero code changes, added the e2e test instead |
| 11 | Phase 8 case-action scope and boundaries | Implemented exactly as scoped — stub built, explicitly not wired into `graph.py`/`main.py`, not exposed to the LLM agents via `tools/registry.py` |
| 12 | TheHive alert status for `close_fp`: `"FP"` vs `"Ignored"` | User verified against the live 5.6.1 UI — `"FP"` is invalid, `"Ignored"` is TheHive's built-in status for this. One-line fix applied |
| 13 | Phase 9 scope (n8n isn't in this repo) | Documentation only — `N8N-INTEGRATION.md` written, no live n8n instance touched or reachable |
| 14 | Phase 10 scope (audit, not padding) | No new tests added speculatively; coverage and doc-drift gaps reported honestly as known issues instead |

### What's still open (see "Known issues / TODOs" above for full detail)
- `requirements-dev.txt` doesn't exist yet (deferred)
- Zero test coverage: `tools/cortex.py`, `tools/elasticsearch.py`, `tools/itop.py`, `tools/registry.py`, `tools/sigma_rules.py`, `prompts/perceiver.py`
- Partial coverage: `tools/thehive.py` (only the read path used by `perceive.py` is directly tested)
- `SOC-3s-ARCHITECTURE-v2.md` §12 (Schemas) and §15 (File Tree) have drifted from the actual code — itemized in Phase 10's drift audit above
- `nodes/case_action.py`'s TheHive write functions are unverified against the live instance (beyond the now-confirmed `"Ignored"` status value)
- ES firewall rule and `SIGMA_RULES_PATH` mount status for live deployment — never confirmed this session, not blocking any code phase
- `perceive.py`'s CanonicalAlert re-normalization gap (§6 sub-task 2) — accepted, not scheduled

### Ready for Tier 0 (advisory-only validation against real Security Onion alerts)
Per `SOC-3s-ARCHITECTURE-v2.md` §19 Phase 11: every verdict should annotate the
case without the pipeline auto-acting, analysts review all `TriageResult`s, and
agreement rate (Cohen's κ) gets tracked before considering Tier 1. That's a live
deployment activity outside this session's scope — the code is now in a state
where that trial can start, contingent on the live-verification items above
(TheHive write endpoints, ES firewall, Sigma rules path) actually being checked
against the real environment first.

## Post-Phase-10 cleanup: schemas.py and §12 resync

Targeted cleanup based directly on Phase 10's drift audit findings, done as a
single focused commit before live n8n connection — not a new phase.

**`schemas.py` changes (the only actual code change):**
- Removed `PerceptionResult` — confirmed dead via `grep` across the entire
  codebase including tests: referenced nowhere outside its own class
  definition. `nodes/perceive.py` writes `TriageState`'s flat `mitre_mapping`/
  `correlation_result` fields directly; nothing ever constructed or consumed
  a `PerceptionResult` instance.
- `ExistingCaseContext` and `ToolCallLogEntry`: confirmed (again) that neither
  exists in `schemas.py` — nothing to remove. `CorrelationResult.
  existing_case_context` is and was a plain `dict`.
- `CorrelationResult.merge_into_case`: confirmed it already exists in
  `schemas.py` (added back in Phase 3) — the earlier drift-audit finding was
  about §12 not documenting it, not about it being missing from code.
- `TriageState`: confirmed it's already flat, matching `graph.py`/`nodes/
  perceive.py`'s actual usage — no code change needed, only §12 needed to
  catch up.

**`SOC-3s-ARCHITECTURE-v2.md` §12 changes:** rewritten field-for-field against
the post-cleanup `schemas.py` — every `Optional`/default/type mismatch from
the Phase 10 audit corrected (`Rule.uuid` required not Optional, no
`Rule.source_engine`, `Host.hostname` Optional, `CortexResult.score` is `int`
not `float`, `CanonicalAlert.host`/`.user`/etc. Optional,
`thehive_observable_ids` is a `dict` not `list[str]`, `EvidencePackage.
threat_intel` is `list[CortexResult]` not `list[dict]`, `TriageResult.
mitre_mapping` is `list[MitreMapping]` not `list[dict]`, and `TriageState` is
flat with no `perception_result` key). `TriageRequest`, `ExistingCaseContext`,
`ToolCallLogEntry`, and the `Impact`/`Likelihood`/`Severity` Literal aliases
removed from the doc since none exist in code. `PerceptionResult` removed from
§12 to match its removal from `schemas.py`.

**Explicitly out of scope, left alone:** §6, §7, §15, and §19 still reference
`PerceptionResult` in prose (Agent 1/2 I/O descriptions and historical
build-order log entries) — the user scoped this cleanup to §12 only. Recorded
above in Known Issues as a residual, not silently dropped.

112/112 tests still passing after the `schemas.py` change (`PerceptionResult`
being dead code, its removal has zero behavioral effect).

## Doc cleanup — PerceptionResult sweep

Documentation only, no `.py` file changes. Single focused commit, done before
connecting to live n8n.

Swept every remaining `PerceptionResult` reference out of
`SOC-3s-ARCHITECTURE-v2.md`:
- **§6 (Agent 1):** the "Implementation note" ending was turned into a proper
  "Output schema" sub-section describing the real contract —
  `{mitre_mapping, correlation_result}` JSON, written directly into
  `TriageState`'s flat fields by `nodes/perceive.py`, with `canonical_alert`
  left as `alert_builder.py` built it (and a pointer to the known sub-task-2
  re-normalization gap already tracked elsewhere in this log).
- **§7 (Agent 2):** both `INPUT:` lines corrected. Verified against
  `nodes/investigate.py` directly (via `grep 'state\.get\|state\['`) rather
  than assuming — it reads `mode`, `canonical_alert`, and (merge mode only)
  `existing_case_context`. It does **not** read `mitre_mapping` or
  `correlation_result` at all, so the fix isn't just a rename — the old text
  implied Agent 2 consumes Agent 1's MITRE mapping, which it never has.
- **§15 (File Tree):** removed from the `schemas.py` and `prompts/perceiver.py`
  entries.
- **§19 (Build Order):** removed from the Phase 3 entry, replaced with the
  actual output schema description.
- **§12:** the two explanatory sentences about the model's removal (written in
  the prior cleanup commit) were rephrased to not use the literal string
  either, since the done-condition for this task was a literal zero-hit grep
  across the file, not "zero *stale* hits."

`grep -rn "PerceptionResult" SOC-3s-ARCHITECTURE-v2.md` → zero hits, confirmed
before committing, as instructed.

**Not swept, out of scope for this commit:** `CHANGES.md`'s own history
(this file, describing what was removed and when — expected to name the
symbol) and `claude-code-session-prompt.md` (the user's original pasted
session-brief document, containing one incidental mention inside an
illustrative example table — not something this session authors or
maintains).

### §15 quick pass — other file tree entries that don't match disk

Originally flagged, not fixed. **Follow-up commit ("final targeted doc fix")
fixed the actively misleading ones** — entries that asserted something false
(a removed dependency still listed as present, a deleted file still shown as
existing). Entries that are merely **incomplete** (missing items, stale "needs
fixing" notes describing work that's since been done) were explicitly left
as-is per the user's instruction — incomplete isn't the same defect as wrong.

**Fixed:**
- [x] `config.py` entry's `Optional:` list — removed `CORTEX_MCP_URL` (gone
  since the Phase 4 revert).
- [x] `requirements.txt` entry — removed `langchain-mcp-adapters` (gone since
  the Phase 4 revert) and `thehive4py` (never actually used — raw `requests`
  throughout).
- [x] `tests/` section — removed the `test_correlate.py ← RETIRE or
  repurpose` line; the file was actually deleted back in Phase 3, not left
  pending a decision.
- [x] §19 Phase 3 entry — marked `(DONE)` with an outcomes summary, matching
  the style already used for Phases 4-10. Includes the honest note that its
  original "test: 10 real alerts" line was never actually run (unit tests
  only, mocked LLM — no live LLM/TheHive/Qdrant reachable from this session).

**Deferred, left as-is (incomplete, not wrong):**
- [ ] `config.py` entry omits `QDRANT_COLLECTION`/`QDRANT_EMBEDDING_MODEL`
  (both real settings).
- [ ] `schemas.py` entry still lists `TriageRequest`, `ExistingCaseContext`,
  the `Impact`/`Likelihood`/`Severity` Literal aliases, and `ToolCallLogEntry`
  — none exist in code (confirmed back in §12's cleanup) but §15's copy of
  this list wasn't touched.
- [ ] `requirements.txt` entry doesn't list `sentence-transformers` (the
  actual Qdrant embedding dependency).
- [ ] `nodes/investigate.py` entry says "needs structured output fix" — true
  before Phase 1 even started, stale phrasing rather than a live TODO.
- [ ] `nodes/format_output.py` entry lists two "fixes needed" already
  resolved before this session began (§18 bugs 3/4).
- [ ] `prompts/perceiver.py` entry's comment "replaces investigator.py for
  Agent 1" is wrong (`investigator.py` still exists, still serves Agent 2)
  and its `build_prompt(mode)` signature doesn't match the real
  `build_prompt()` (no args) — noted back in Phase 3's section of this log,
  never corrected in §15.
- [ ] `prompts/analyst.py` entry: "add mitre_mapping validation instruction"
  — already done, in Phase 6.
- [ ] `tests/` section still doesn't list `test_investigate.py`,
  `test_case_action.py`, `test_e2e.py`, `test_thehive.py`, or
  `test_qdrant.py` (all real files).

§15 remains a mix of accurate-but-incomplete and now-mostly-not-actively-wrong
— still don't treat it as a source of truth for "what's done"; §19 is that
now that Phase 3 is marked `(DONE)` too.

**One more finding, adjacent but real:** §19's Phase 3 entry was never marked
`(DONE)` with a details summary the way Phases 4 through 10 were — an
oversight from earlier in the session. **Fixed in the follow-up "final
targeted doc fix" commit** — see the §15 quick-pass section above.

## Final targeted doc fix (last doc cleanup before Tier 0)

Documentation only, single commit. Fixed only the actively misleading §15
entries flagged in the prior commit (a removed dependency shown as present, a
deleted test file shown as existing) — not the whole file tree. Also marked
§19's Phase 3 entry `(DONE)`, closing the last item from the prior commit's
findings. See the "Fixed" / "Deferred" split in the §15 quick-pass section
above for exactly what changed and what's intentionally still left incomplete.

112/112 tests passing (no `.py` files touched).

---

# v3-final

New session (2026-08-03), same worktree. `SOC-3s-ARCHITECTURE-v3-final.md` and
`claude-code-v3-final-prompt-2.md` were added; the old `SOC-3s-ARCHITECTURE-v2.md`
and `claude-code-session-prompt.md` had already been deleted by the user before
this session started.

## Reconciliation (before any code changes)

**Finding, reported and resolved before touching anything:**
`claude-code-v3-final-prompt-2.md` (300 lines) turned out to be byte-for-byte
the same generic v2-era template as the very first session's
`claude-code-session-prompt.md` — "Phase 1 bug fixes... Phase 10 Tests,"
references to `ARCHITECTURE.md §18/§19`, `architecture-revision-v2.md`, the old
cortex-mcp Phase 4 rules. Zero mentions of Suricata, Kibana, FP tracking, or
Phases A-G. It is not a v3 task list despite its filename and the session's own
framing of it as one. The actual Phase A-G build order (and the "Phase E
deletion list" the session's opening instructions pointed at) only exists in
`SOC-3s-ARCHITECTURE-v3-final.md` §13. Flagged to the user rather than guessed
around. **User decision: delete the stale file, treat §13 as the authoritative
task list.**

**File inventory vs. §13 Phase E's "keep" list** (`ARCHITECTURE.md` i.e. the v3
doc, `CHANGES.md`, `N8N-INTEGRATION.md`): everything else in the repo matched
the prior session's end state (Phases 1-10 + doc cleanups) — no other
superseded drafts, except one leftover: `CONTEXT.md.save` (a backup of the
very first, pre-v2 architecture doc, never cleaned up across the whole prior
session).

**Kibana grep** (`grep -rli "kibana" --include="*.py" --include="*.md" .`):
one file matched — `SOC-3s-ARCHITECTURE-v3-final.md` itself, and every hit is
inside its own "tried and reverted" record (§1, §11's tool-inventory comment,
§12's rejected-decisions table, §13's Phase F verification step) — documenting
the decision *not* to use Kibana, not presenting it as live. Zero hits in any
`.py` file (`tools/`, `nodes/`, `prompts/` all clean). Zero hits in
`CHANGES.md` — Kibana was never part of this session's own history to begin
with, so there was nothing to preserve there. No cleanup needed on this front.

## Phase E — cleanup

Deleted per §13 Phase E ("delete all superseded prompt/architecture drafts...
keep: ARCHITECTURE.md, CHANGES.md, N8N-INTEGRATION.md") and the user's
resolution of the prompt-file finding above:
- `claude-code-v3-final-prompt-2.md` — stale v2-era template, not a real v3
  task list (see reconciliation above)
- `CONTEXT.md.save` — leftover backup of the original pre-v2 architecture doc

112/112 tests passing (no `.py` files touched — this phase was deletions of
two `.md`-adjacent files only).

## Phase A — alert_builder.py event_data fix

### Research: read Security Onion's actual ingest pipelines before writing code

Per explicit instruction, read `so-ingest-reference/salt/elasticsearch/files/
ingest/{common,common.nids,suricata.alert,strelka.file,sysmon,win.eventlogs,
global@custom,common.ip_validation,ecs}` and
`so-ingest-reference/salt/logstash/pipelines/config/so/0012_input_elastic_agent.conf.jinja`
(a real, sparse-checked-out clone of Security Onion's own repo, present in the
main checkout at `/home/ai-vm/agent-service/so-ingest-reference`, outside this
worktree) before touching `alert_builder.py`. Findings reported to the user
before writing code:

- Suricata (`suricata.alert` → `common.nids` → `common`): confirms §7's SID
  finding — `rule.uuid` is the numeric SID, not a MITRE ID. Fields land at the
  top level (`rule.name`, `rule.uuid`, `rule.reference`, `rule.ruleset`,
  `event.severity`/`.severity_label`), no `event_data` nesting.
- YARA/Strelka (`strelka.file`): `rule.uuid` is set to `rule.name` itself, not
  a separate numeric ID — the ingest pipeline literally does
  `rule.uuid = rule.name`. Arbitrary YARA rule `meta` keys flatten to
  `rule.{key}`, so MITRE tagging is possible per-rule but never structurally
  guaranteed — confirms the doc's "graceful empty-return" call. No `event_data`
  nesting.
- Sigma: **no dedicated ingest pipeline exists at all** (confirmed via
  `grep -rli "sigma\|elastalert"` across the whole reference repo — zero hits).
  ElastAlert2 queries already-ingested telemetry and embeds the matched
  document under `event_data`; two different agents produce that telemetry
  with different field layouts (Winlogbeat+Sysmon vs Elastic Agent/Defend) —
  reported to the user as a real ambiguity before writing extraction code
  (see "Questions asked" below).

### User-provided confirmed facts (superseded some of the pipeline-derived detail)

The user then provided a confirmed field-path list from live captured payloads
across the project (not from `so-ingest-reference` alone), and explicitly
deleted `alert-sample.json` — the single sample the previous session's
`test_e2e.py` fixture was built from — with the instruction not to reference
or restore it, and to design `alert_builder.py` from the pipeline research
plus these confirmed facts, not one sample. Confirmed facts used directly:
Sigma's `event_data.{host,user,process}.*` paths (all genuinely optional, not
tied to one telemetry source), Suricata's top-level `rule`/`source`/
`destination`/`network`/`event` fields (no `event_data`, no process/user/hash),
YARA's top-level `rule`/`file` fields (`rule.uuid == rule.name`, no
`event_data`).

### Implementation

`alert_builder.py`:
- `_parse_rule()`: now tries a structured top-level `raw_alert["rule"]` dict
  first (Suricata/YARA), falling through to the existing description-regex/tag
  parsing only when absent (Sigma, or any alert without a `rule` dict).
- New: `_extract_host_from_event_data()`, `_extract_user_from_event_data()`,
  `_extract_process_from_event_data()` (Sigma) — structured extraction from
  `raw_alert["event_data"]`, preferred over the regex/description fallback,
  which still runs when `event_data` is absent or a given sub-object is empty.
  A couple of extra fallback locations beyond the user's confirmed list are
  also checked defensively (top-level `event_data.hash.*`, `process.ppid`) —
  not independently confirmed live, based on the `sysmon` ingest pipeline
  source, kept as harmless additional coverage since every lookup degrades to
  `None` rather than raising.
- New: `_extract_network_from_raw_alert()` (Suricata), `_extract_file_from_raw_alert()`
  (YARA) — structured top-level extraction, wired into `build_canonical_alert()`
  (previously `network`/`file` were always `None`).
- New: `_merge_hashes()` — merges structured-extraction hashes into the same
  `Observables.hashes` bundle the IOC-tagged `observables` array already
  populates, deduped.
- New: `_as_dict()` helper, applied to every nested-object lookup in this
  file. **Found and fixed a real bug while writing tests, not by inspection:**
  n8n's Alert Builder envelope has a top-level `source` key that's a *string*
  (the source system, e.g. `"security-onion"`) — this collides in name with
  Suricata's ECS `source` object (network source ip/port). The first version
  of `_extract_network_from_raw_alert()` called `.get()` on it directly and
  crashed with `AttributeError: 'str' object has no attribute 'get'` against
  the *existing* Sigma test fixture (which has always had `"source":
  "security-onion"`). `_as_dict()` makes every nested-object lookup in this
  file degrade to "field absent" on a type mismatch instead of raising.

`schemas.py`: `Process` gained two fields the confirmed extraction needs and
didn't have a home for: `working_directory` and `parent_command_line`.

`tests/test_alert_builder.py`: 5 new tests — event_data taking precedence over
(deliberately conflicting) description text, event_data with a missing
sub-object (`parent`) leaving those fields `None` rather than erroring,
Suricata structured rule+network extraction, the `source`-string-collision
regression case above, YARA structured rule+file extraction (including
`rule.uuid == rule.name`).

`tests/test_e2e.py`: **fixed a break caused by the `alert-sample.json`
deletion** — its fixture builder read that file directly. Replaced with
`_build_sigma_raw_alert()`, a hand-built fixture using the same confirmed
`event_data` field paths (not derived from any sample). Same two tests as
before, same assertions, just a different fixture source.

Also updated two stale `SOC-3s-ARCHITECTURE-v2.md` section references left
over in `alert_builder.py`/`tests/test_alert_builder.py` from before this
session's v3 migration, to point at `SOC-3s-ARCHITECTURE-v3-final.md` §5
instead — noticed while editing these files, in scope since these are exactly
the files this phase touches.

### Questions asked to user (resolved)

| Question | Answer |
|---|---|
| Two different Sigma-alert telemetry shapes exist depending on the source agent (Winlogbeat+Sysmon vs Elastic Agent/Defend), but only one is independently confirmed live — build for both from pipeline source, restrict to the confirmed one, or wait for a live Sysmon sample? | Build for both, from pipeline source; note the Sysmon path as unverified. (Superseded in part by the user's follow-up: don't design around any single sample at all — confirmed facts + pipeline research instead.) |

117/117 tests passing (112 before this phase, 5 net new). Syntax check and
import check also passed manually.

## Phase B — rename and extend detection_rules.py

`tools/sigma_rules.py` → `tools/detection_rules.py` (deleted the old file, not
a `git mv` — content changed enough that a straight rename didn't make sense).
Public entry point is now `get_rule_source(rule_uuid, source_engine=None) ->
dict`, dispatching per §11's confirmed order: explicit `source_engine` hint
routes straight to that engine's lookup; no hint tries Sigma YAML → Suricata
`.rules` metadata → YARA graceful return, in that order, returning on the
first `found: true`.

**Suricata parser** (`_get_suricata_rule_source`/`_extract_suricata_rule`),
built from §7's confirmed rule format and parser logic: scans
`SURICATA_RULES_PATH` (new setting, default `/opt/so/rules/nids/suri/all.rules`
— a single combined file, not a per-rule directory like Sigma) line by line,
skips lines starting with `#` (disabled rules), matches on the literal
`sid:{uuid};` substring (the trailing `;` boundary prevents partial-number
false positives — e.g. a lookup for `"10665"` cannot match `sid:2010665;` —
tested explicitly). Extracts `msg:"..."` as title and parses the `metadata:`
block (comma-separated `key value` pairs) for `mitre_technique_id`/`_name`,
`mitre_tactic_id`/`_name`. Missing MITRE metadata is treated as a normal,
common, non-error case (confirmed: only 50.2% of active rules have it) —
returns `found: true` with empty `mitre_attack`/`mitre_tactics` lists, not an
error or a gap marker.

**YARA graceful return** (`_get_yara_rule_source`): always `found: false` with
empty MITRE lists and an explanatory `error` string, never raises — YARA rules
have no centrally indexed lookup-by-UUID mechanism and no native MITRE tagging
convention (confirmed via the `strelka.file` ingest pipeline research from
Phase A). `source_engine="strelka"` is accepted as an alias and routes here
too, since Strelka is the YARA execution engine, not a separate rule format.

**Sigma path unchanged in behavior**, just moved and given a `source_engine:
"sigma"` field in its output dict for consistency with the other two engines
(the existing dict shape didn't have this field before — nothing consumed it,
so this is purely additive).

**Fixed two broken references discovered while making this change, not just
the rename itself:**
- `tools/registry.py`'s `sigma_rule_lookup` tool wrapper imported from the
  deleted module — updated the import, left the tool's name/signature
  unchanged (splitting/renaming the tool itself into `detection_rule_lookup`
  is Phase C's job, per §13, not this one).
- `nodes/perceive.py`'s `_extract_techniques_from_rule()` (the deterministic
  fallback used when Agent 1's LLM output doesn't parse) also imported
  directly from the deleted module — updated the import, **and** fixed a real
  behavioral gap this exposed: it was reading `rule.get("tags", [])`, a
  Sigma-only field. Suricata's output dict has no `tags` key at all — it would
  have silently returned an empty technique set for every Suricata-sourced
  fallback lookup. Switched to `rule.get("mitre_attack", [])`, which both
  engines' output dicts populate (Sigma: raw `"attack.txxxx"` tag strings;
  Suricata: bare `"Txxxx"` IDs) — `MITRE_TECHNIQUE_RE`'s `(?:attack\.)?` prefix
  is already optional, so the same extraction regex handles both forms
  without new branching. Also now passes `alert.source_engine` as the
  `source_engine` hint, avoiding the full fallback-chain walk when the engine
  is already known.

`tests/test_detection_rules.py` — **new, this module had zero test coverage
before this phase** (flagged in Phase 10's audit): 12 tests — Suricata with
MITRE metadata, without it (not an error), a commented rule correctly skipped,
an unknown SID, the sid-boundary false-positive case explicitly, a missing
rules file, YARA's graceful return, the `strelka` alias, both no-hint dispatch
paths (finds via Suricata when Sigma misses; falls all the way through to
YARA when nothing matches), and baseline Sigma found/not-found coverage (also
previously untested).

129/129 tests passing (117 before this phase, 12 net new). Syntax check,
import check, and `tools.registry` tool listings also verified manually.

## Phase C — split tool lists in registry.py

`tools/registry.py`'s old single `TOOLS` list (shared by both agents) is
replaced with two disjoint lists, per §1/§6/§8/§13's "no tool duplication"
principle: Agent 1 (perceive) owns open-case correlation and MITRE tag
extraction; Agent 2 (investigate) owns closed-case history, telemetry, and
enrichment.

```python
PERCEPTION_TOOLS = [detection_rule_lookup, thehive_open_cases, qdrant_retrieve_mitre]
INVESTIGATION_TOOLS = [thehive_search_closed, elasticsearch_query, itop_asset_lookup, qdrant_retrieve, cortex_analyze]
```

A module-level `assert not (PERCEPTION_TOOLS names & INVESTIGATION_TOOLS
names)` enforces the zero-overlap invariant at import time — if a future edit
accidentally adds a tool to both lists, the service fails to start rather than
silently violating the design principle.

**Renames/splits, not just a list re-shuffle:**
- `sigma_rule_lookup` → `detection_rule_lookup`, wrapping Phase B's
  `get_rule_source`, with a new optional `source_engine` param so Agent 1 can
  pass the alert's known engine (`alert.source_engine`) and skip the
  no-hint fallback chain. Agent 1-exclusive.
- The old generic `thehive_search` (three modes: `open_cases`/`closed_cases`/
  `get_case`) is split into `thehive_open_cases` (Agent 1) and
  `thehive_search_closed` (Agent 2) — one tool, one job, per engine
  ownership. The `get_case` mode is dropped entirely (see discrepancy note
  below).
- `qdrant_retrieve`'s `collection` param narrowed from
  `mitre_attack`/`playbooks`/`cve` to just `playbooks`/`cve` — MITRE search
  moved exclusively to `qdrant_retrieve_mitre` (Agent 1-only), so Agent 2's
  `qdrant_retrieve` can no longer search MITRE at all.

**Known discrepancy vs §11, not yet resolved:** §11's broader tool inventory
lists a case-detail lookup (`get_case_full` in `tools/thehive.py`, still
present and functional — just no longer wrapped as a registered tool) as
something Agent 1 needs "on merge" to pull full context from the matched
case. Phase C's literal tool-list scope (§13) doesn't include it in either
list. Flagging here rather than silently dropping the capability or silently
adding it back without confirmation — Agent 1 currently gets merge-mode
context only from `correlate.py`'s `existing_case_context` (already gathered
during the correlate node, not from a tool call), not from a live
`get_case_full` call during investigation. Needs a decision on whether that's
sufficient or whether `get_case_full` should be added to `PERCEPTION_TOOLS`
in a later phase.

**`nodes/investigate.py` updated to match:** import/usage switched from
`TOOLS` to `INVESTIGATION_TOOLS`; `_build_from_tool_results()`'s fallback-
bucketing lost its dead `sigma_rule_lookup` branch (Agent 2 never has this
tool, so it could never fire) and renamed its `thehive_search` branch to
`thehive_search_closed`; the `historical_context` bucket key
`mitre_candidates_from_rag` renamed to `qdrant_rag_results` (Agent 2's
`qdrant_retrieve` is cve/playbooks only now, never MITRE — the old name was
actively misleading about what could be in it).

**Real bug found and fixed while updating tests for this phase, unrelated to
the rename itself:** `_try_parse_json()` in `nodes/investigate.py` extracted
JSON via a naive `text.find("{")` / `text.rfind("}")` substring slice. Tool
results that are list-shaped — `elasticsearch_query`, `qdrant_retrieve`,
`thehive_search_closed` all return lists — still contain a valid `{...}`
substring inside their `[...]` wrapper (e.g. `'[{"title": "x"}]'`), so the old
code silently returned just the first dict element instead of the actual
list, or `None`. Every `isinstance(parsed, list)` check gating those three
tools' fallback-bucketing branches in `_build_from_tool_results` was
therefore dead code in practice — confirmed directly via a REPL check before
fixing. Rewrote to try `json.loads(text)` on the whole (fence-stripped) text
first, which correctly preserves whichever shape the content actually is,
falling back to the old brace/bracket-extraction heuristic only for text with
real surrounding prose. Caught by a new test
(`test_build_from_tool_results_buckets_qdrant_and_thehive_closed`) written for
this phase, not by pre-existing coverage.

`tests/test_investigate.py` updated: two existing tests referencing the
removed `sigma_rule_lookup` tool renamed/rewritten against `itop_asset_lookup`
(still in `INVESTIGATION_TOOLS`); one new test added for the qdrant/thehive
list-shaped bucketing (which exposed the `_try_parse_json` bug above).

130/130 tests passing (129 before this phase, 1 net new — 2 tests renamed in
place rather than added). Syntax check, import check, `main.py` route check,
and the `PERCEPTION_TOOLS`/`INVESTIGATION_TOOLS` zero-overlap assertion all
verified manually.

## Phase C follow-up — get_case_full added to PERCEPTION_TOOLS

Closes the discrepancy flagged at the end of Phase C. §11's tool inventory
explicitly lists `get_case_full(case_id) # Agent 1, on merge` even though its
own `PERCEPTION_TOOLS` code block in the same section only names 5 tools —
an inconsistency inside the architecture doc itself. Resolved in favor of
including it: `get_case_full` is now wrapped and registered, so Agent 1 can
read a merge candidate's full content (description, severity, tags, metrics,
custom fields, summary) after `thehive_open_cases` finds it, rather than
deciding match strength and kill-chain progression from the shallow
open-cases list alone.

## Phase G (pulled forward ahead of Phase D) — FP history tracking

Originally scheduled after Phase F, pulled forward because Phase D's prompt
work (documenting Agent 1's tool set and call order) can't be written
honestly without `get_fp_signal`/`thehive_fp_history` actually existing —
writing prompt text for tools that don't exist yet would leave the prompt and
the registered tool list out of sync the moment Phase D landed.

**Scope correction before starting:** the Phase D task description this
session was given named `get_fp_signal` as one of "5 PERCEPTION_TOOLS", but
§7a and §13 of the architecture doc both independently scope Phase G as
adding *two* tools to `PERCEPTION_TOOLS` — `get_fp_signal` (always-run) and
`thehive_fp_history` (conditional) — making 6 total once `get_case_full` is
included, not 5. Flagged and confirmed before building, per doc.

**`tools/fp_tracking.py`** (new): SQLite-backed FP-history counter per §7a's
design, grounded in AACT (Turcotte, Labrèche, Paquette — arXiv:2505.09843,
2025)'s finding that recent-past triage decisions predict future ones — and
critically, that this must be captured as **two separate time windows**, not
one running total: short-term (24h, active-incident noise) and long-term
(30d, chronic baseline noise like a scanner). A flat all-time counter erases
exactly this distinction.

- `fp_events` table (`rule_uuid`, `host`, `is_fp`, `triage_timestamp`,
  `verdict_confidence`) with an index on `(rule_uuid, host, triage_timestamp)`,
  schema-on-first-use via `CREATE TABLE IF NOT EXISTS` — no migration step,
  no crash on a missing db file (first run creates it and the containing
  directory).
- `get_fp_signal(rule_uuid, host)` — always-run, local, no network call.
  Returns `{short_term_fp_rate, short_term_total, long_term_fp_rate,
  long_term_total}`. Gracefully returns all-zero on missing rule_uuid/host
  rather than erroring.
- `thehive_fp_history(rule_uuid, host, limit=3)` — the conditional TheHive
  query for the actual past-closure reasoning text. §7a's pseudocode frames
  the `long_term_fp_rate > 0.5 AND long_term_total >= 5` threshold as
  something the calling agent checks before deciding to call this — but it's
  gated **in code** here instead (calls `get_fp_signal` internally first,
  returns `[]` without touching TheHive if the threshold isn't met), matching
  this repo's established pattern of enforcing safety/cost guardrails
  defensively rather than trusting the LLM to always follow prompt
  instructions. Makes the gate unit-testable independent of any LLM.
- `record_triage_outcome(rule_uuid, host, is_fp, verdict_confidence)` — one
  row per completed triage. `TriageVerdict` has no single top-level
  confidence field (only per-MITRE-mapping `confidence`), so
  `verdict.likelihood` (unlikely/possible/likely/near_certain — Agent 3's own
  stated confidence in its verdict) is used as the `verdict_confidence`
  proxy, documented in the docstring rather than silently assumed.

**`tools/thehive.py`**: added `search_fp_history(rule_uuid, host, limit=3)`,
following the existing `search_closed_cases` request pattern but filtering
TheHive alerts (not cases) on `status: ["Ignored"]` — confirmed elsewhere in
this doc as the real FP-close status (`"FP"` does not exist on live TheHive
5.6.1). Also added `get_case_full` to this module's public import surface
used by `tools/registry.py` (function itself pre-existed from an earlier
phase, just wasn't wrapped as an agent tool until now).

**`config.py`**: `FP_DB_PATH` setting, default `./data/fp_events.db`,
overridable via env var — same pattern as `SIGMA_RULES_PATH`/
`SURICATA_RULES_PATH`. **`.gitignore`**: added `data/*.db` so the runtime
database is never committed.

**`tools/registry.py`**: `PERCEPTION_TOOLS` now holds 6 tools —
`get_fp_signal`, `thehive_fp_history`, `detection_rule_lookup`,
`qdrant_retrieve_mitre`, `thehive_open_cases`, `get_case_full` — ordered to
match the intended call sequence. Zero-overlap assertion against
`INVESTIGATION_TOOLS` re-verified, still holds.

**`nodes/format_output.py`**: wired `record_triage_outcome()` into the
full-verdict branch (mode `new` with a `TriageVerdict` present) — not the
dedup path (no verdict exists), not the merge/delta path (`DeltaVerdict` has
no TP/FP concept, only a delta on an already-open case), matching §7a's "one
row per completed triage... reflects the agent's own judgment history," which
only applies where a real TP/FP/needs_review judgment was made. No-ops
gracefully via `record_triage_outcome`'s own guard when the alert has no host
(e.g. a network-only Suricata alert).

**`nodes/perceive.py`**: `PERCEPTION_MAX_TOOL_CALLS` bumped from 4 to 6 to
match the tool-call-order budget documented in the Phase D prompt update
below — the old limit predates this phase and would have cut off the fuller
6-step sequence (`get_fp_signal` → optional `thehive_fp_history` →
`detection_rule_lookup` → optional `qdrant_retrieve_mitre` →
`thehive_open_cases` → optional `get_case_full`) partway through.

**Real bug caught while wiring `record_triage_outcome` into
`format_output.py`, not part of the original plan:** the first test run of
`test_e2e.py` after this wiring left a real `./data/fp_events.db` file on
disk — the end-to-end test builds an alert with a real hostname and runs the
full graph unmocked, so `record_triage_outcome()` wrote to the actual
production default path as a side effect of running the test suite. Fixed by
adding `tests/conftest.py` with an autouse fixture that redirects
`tools.fp_tracking.FP_DB_PATH` to a per-test `tmp_path` for every test in the
suite — no test should ever be able to touch real application state,
regardless of which node or tool a given test happens to exercise.

`tests/test_fp_tracking.py` (new, 9 tests): schema creation on first use with
no pre-existing db file, graceful no-op on missing rule_uuid/host (both for
`get_fp_signal` and `record_triage_outcome`), writes on both TP and FP
outcomes, short-term vs long-term window correctness (a 10-day-old event
counts toward the 30d window but not the 24h one), per-rule/per-host
scoping, and three cases for the conditional gate (below rate threshold,
above both thresholds, above rate but below sample-count threshold).

`tests/test_thehive.py`: added coverage for `search_fp_history` (4 tests —
had none before) and `get_case_full` (2 tests — also had none before,
despite the function existing since an earlier phase).

`tests/test_format_output.py`: added 2 tests for the new wiring (`Host`
import added to fixture helper) — records on a host-bearing alert, skips
recording (no file created) on a hostless one.

## Phase D — update prompts

**`prompts/perceiver.py`**: full rewrite of the tool section. Documents all 6
`PERCEPTION_TOOLS` with the explicit call order from §7a/the task brief:
`get_fp_signal` (free, always first) → `thehive_fp_history` (conditional on
the threshold, explicitly told it queries nothing below it) →
`detection_rule_lookup` (with the explicit warning that a Suricata rule_uuid
is the SID, a lookup key, **never** a MITRE technique ID itself) →
`qdrant_retrieve_mitre` (MITRE inference/kill-chain only, only if no rule
tags found) → `thehive_open_cases` (correlation, reason about match
strength, not string equality) → `get_case_full` (only after a candidate is
found, to read its actual content before the merge/new decision). Added the
§7a guardrail verbatim in spirit: a high FP rate informs confidence, it never
auto-decides the verdict. Tool-call budget bumped from 4 to 6 in the prompt
text to match the fuller sequence (see the matching code change above).

**`prompts/investigator.py`**: full rewrite. Removed all `sigma_rule_lookup`
references (previously in the main tool list AND 3 of the 5 profile blocks —
`endpoint_behavior`, `network_anomaly`, `log_anomaly` all told Agent 2 to use
a tool it no longer has). Replaced the old generic `thehive_search` with
`thehive_search_closed`, narrowed `qdrant_retrieve`'s documented `collection`
values from `mitre_attack`/`playbooks`/`cve` to `cve`/`playbooks` only, and
renamed the `historical_context.mitre_candidates_from_rag` output key to
`qdrant_rag_results` (the prompt's JSON output template still had the old
key name — Phase C had already renamed it in `nodes/investigate.py`'s actual
handling code, so the prompt and the code disagreed on the schema until now).
Cortex discipline instruction (check `canonical_alert.cortex_results` first,
skip common infrastructure) was already present from an earlier phase and is
preserved, now stated with the exact field name. Added an explicit note that
rule/MITRE-tag lookup and open-case correlation already happened in Agent 1
and Agent 2 does not have those tools — added because of a real gap this
surfaced: Agent 2's `rule_context.known_fp_conditions`/`detection_logic`
output fields can no longer be populated from a live rule-source fetch (that
tool moved to Agent 1-exclusive in Phase C); Agent 2 now has to reason about
them from the `alert.rule` fields already in its context instead. §8's own
"Structured output: Unchanged from v2" note doesn't address this — flagging
it here rather than pretending the schema and the tool capability are still
aligned. No Kibana references anywhere (confirmed by test, see below).

`tests/test_prompts.py`: replaced the now-false `"sigma_rule_lookup" in
prompt` assertion with a dedicated `test_investigator_prompt_has_no_agent1_
exclusive_tools` covering all 7 Agent-1-exclusive names plus "kibana", plus
tests for the cortex-discipline instruction and the cve/playbooks-only
`qdrant_retrieve` scope.

`tests/test_perceiver_prompt.py` (new, 7 tests) — `prompts/perceiver.py` had
zero test coverage before this phase: all 6 tools documented, `get_fp_signal`
called first, the 0.5/5-sample threshold documented, the FP guardrail
language present, the Suricata-SID warning present, `get_case_full`
documented after `thehive_open_cases` (not before), and no Kibana reference.

156/156 tests passing (130 before this phase — 9 fp_tracking + 2
format_output + 9 thehive + 12 net-new/replaced prompt tests + 7 perceiver
prompt tests, with some renames absorbed into that delta). Syntax check,
import check, `main.py` route check, `python config.py` (confirms
`FP_DB_PATH` resolves), and the 6-tool `PERCEPTION_TOOLS`/5-tool
`INVESTIGATION_TOOLS` zero-overlap assertion all verified manually.

### Questions asked to user (resolved)

| Question | Answer |
|---|---|
| `get_fp_signal` doesn't exist yet (Phase G territory, with its own open SQLite-path question) — how should Phase D handle documenting a tool that isn't built? | Pull Phase G forward and build it now, rather than writing prompt text for a nonexistent tool or documenting only 4 real tools. |
| §7a/§13 both scope Phase G as adding `get_fp_signal` AND `thehive_fp_history` (6 tools total with `get_case_full`), not just the 5 the task brief named — proceed with both? | Yes, build both — architecture doc is correct, the brief was short by one. |
| Where should the FP-tracking SQLite file live? No existing data/var convention in the repo. | `./data/fp_events.db`, create the directory if missing, add `data/*.db` to `.gitignore`. |

### Note on this session's MCP tooling

The user reported connecting an Elasticsearch MCP and a TheHive MCP to this
session for read-only field/behavior verification against the live
instances, with explicit ground rules (read-only, flag discrepancies before
changing code, don't re-open settled decisions without flagging). Searched
for these tools before starting Phase G and found neither registered in this
session's available tools — proceeded from the architecture doc's confirmed
spec and flagged the gap rather than fabricating a live verification that
didn't happen. If the MCP connection is expected to be live, worth checking
the session/tool configuration before the next phase that would benefit from
it (Phase F's end-to-end validation, or any future live-field confirmation
work).

### Known limitation, accepted for now: Agent 2's rule_context gap

The Phase D `investigator.py` update noted that Agent 2's `rule_context.
known_fp_conditions`/`detection_logic` output fields can no longer be
populated from a live rule-source fetch — `detection_rule_lookup` moved to
Agent 1-exclusive in Phase C, and no equivalent tool was added to
`INVESTIGATION_TOOLS`. Decision: accept this for now rather than add a tool
back or duplicate rule-source access across both agents. Agent 1's
`mitre_mapping[].basis` strings (its stated reasoning for each technique
inference) are the mechanism carrying the most load-bearing rule context
forward into the pipeline — Agent 2 and Agent 3 both see the alert's
`mitre_mapping` in their input. If Tier 0 testing shows Agent 2 producing
poor FP assessments specifically traceable to not seeing the rule's own
documented false-positive conditions, the fix is to add the rule source (or
just its `known_fp_conditions`/description) as a field on the handoff from
Agent 1 into `investigate.py`'s human message — not to re-grant Agent 2 a
rule-lookup tool, which would reintroduce the duplication Phase C's split
was designed to remove.

## Phase E — cleanup: delete outdated files (verified, not re-run)

Re-checked against §13's Phase E instruction before doing any deletion work
this session. Finding: **Phase E was already completed**, in commit
`76d647d` ("v3-final: reconciliation + Phase E cleanup"), before this
session's Phase A work even started — it deleted
`claude-code-v3-final-prompt-2.md` (stale v2-era template) and
`CONTEXT.md.save` (leftover pre-v2 doc backup), and committed the user's own
prior deletion of `SOC-3s-ARCHITECTURE-v2.md` and
`claude-code-session-prompt.md`.

Confirmed against current disk state before concluding there was nothing
left to do: repo root holds exactly `SOC-3s-ARCHITECTURE-v3-final.md`,
`CHANGES.md`, `N8N-INTEGRATION.md` (§13's explicit keep list) plus
`CLAUDE.md` (project instructions, a different category, not a
prompt/architecture draft). A repo-wide search for `*.save`, `*draft*`,
`*OLD*`, `*v2*`, `*prompt-2*`, `*session-prompt*` (excluding `.git/`,
`so-ingest-reference/`, `__pycache__/`, `.pytest_cache/`) returned zero
matches. Nothing deleted this session — nothing on disk matched the
deletion criteria.

## Phase F — end-to-end validation

- `pytest tests/ -v`: **156/156 passing.**
- `grep -rli "kibana" tools/ nodes/ prompts/`: **zero hits.** (The only
  "kibana" string anywhere in the repo is the intentional "tried and
  reverted" documentation inside `SOC-3s-ARCHITECTURE-v3-final.md` itself —
  outside the scope of this check, and correctly so: it's a historical
  record of a rejected design, not live code or a live prompt.)
- `PERCEPTION_TOOLS`/`INVESTIGATION_TOOLS` zero-overlap: **holds.**
  `PERCEPTION_TOOLS` (6): `detection_rule_lookup`, `get_case_full`,
  `get_fp_signal`, `qdrant_retrieve_mitre`, `thehive_fp_history`,
  `thehive_open_cases`. `INVESTIGATION_TOOLS` (5): `cortex_analyze`,
  `elasticsearch_query`, `itop_asset_lookup`, `qdrant_retrieve`,
  `thehive_search_closed`. No name appears in both — verified both via the
  module-level `assert` in `tools/registry.py` (which import already
  exercises on every test run) and independently at the shell.

### Open items carried forward (not blocking, not silently resolved)

1. **Agent 2's rule_context gap** — accepted as a known limitation, see
   above. Revisit only if Tier 0 testing shows a concrete FP-assessment
   quality problem traceable to it.
2. **MCP tooling** — the user reported connecting Elasticsearch and TheHive
   MCP tools to this session for live read-only verification during Phase G,
   but neither was found registered in the session's available tools when
   searched for. Phase G proceeded from the architecture doc's confirmed
   spec instead. Worth confirming the MCP connection before any future work
   that specifically needs live-instance verification (e.g. confirming
   TheHive's actual alert query shape for `search_fp_history`/
   `thehive_fp_history` against the real API, which is currently built from
   the same unverified convention as the pre-existing `search_open_cases`/
   `search_closed_cases` functions — those already carry a documented
   "UNVERIFIED against the live TheHive instance" caveat for the write-path
   functions in the same module; the v1 query-endpoint shape used by all of
   `search_open_cases`/`search_closed_cases`/`search_fp_history` has not
   itself been confirmed against a live 5.6.1 instance the way
   `get_full_alert_with_analysis` was).
3. **Suricata rules file staleness** — `SURICATA_RULES_PATH` defaults to a
   single combined file (`/opt/so/rules/nids/suri/all.rules`); no code in
   this repo reloads it, so a long-running service process will serve stale
   `detection_rule_lookup` results if the file is updated on disk after
   startup. Not addressed this session — flagging since it wasn't raised
   before and could matter for the eventual n8n-connected deployment.
4. **`PERCEPTION_MAX_TOOL_CALLS` = 6 is a hard ceiling, not a true budget** —
   the prompt tells Agent 1 to use at most 6 calls matching the 6 available
   tools, meaning there is zero slack for a retry (the prompt's own "retry
   ONCE on wrong parameter name" instruction) without exceeding it. Not
   changed this session since it wasn't asked for; noting in case retries in
   practice turn out to need the failed attempt not to count against the
   budget.

Phase G, D, E, and F are now complete against the v3-final build order. Only
Phase G's original scope (already built) and these four open items remain
outstanding for a future session.

Note: open item 4 above (`PERCEPTION_MAX_TOOL_CALLS` = 6, zero retry slack)
was resolved by the pre-Tier-0 fix immediately following this phase — bumped
to 7. See git commit `90e59ef`.

## Post-Phase-F — `detection_rule_lookup` rewritten to use Elasticsearch, not the filesystem

**What changed and why.** Phase B built `tools/detection_rules.py` to read
Sigma YAML from `SIGMA_RULES_PATH` and scan Suricata's `all.rules` file for
`sid:NNNN;` lines. Live investigation of the deployment found this could
never fully work: the files under `/opt/so/rules/elastalert/rules/*.yml` are
**compiled ElastAlert2 output**, not native Sigma — they use
`detection_public_id` instead of `id`, an `eql:` filter instead of
`detection:`, and the MITRE `tags:` field is **stripped during compilation**.
That path could never yield MITRE mappings for Sigma alerts, no matter how
the parser was tuned.

Security Onion turns out to store the full native source for **all three**
detection engines — Sigma, Suricata, YARA — in one Elasticsearch index,
`so-detection` (74,888 docs, confirmed live), with unmodified rule source in
`so_detection.content` and tags intact. `tools/detection_rules.py` now issues
one query against that index (`term` match on `so_detection.publicId`,
matching `rule.uuid` exactly across all three engines: UUID for Sigma, SID
for Suricata, rule name for YARA) and dispatches MITRE parsing on the index's
own `so_detection.language` field — never on the caller's `source_engine`
hint, which is now accepted for call-site compatibility only. Reused
`tools/elasticsearch.py`'s existing `_es_post`/`_headers` client directly —
no second ES connection was created.

**Confirmed MITRE coverage** (verified two independent ways — wildcard and
strict-regexp queries returning the same count, plus a manual check that all
10 of the highest-volume rules actually firing on this deployment carry
technique IDs):

| Engine | Total | Enabled | With MITRE | Coverage |
|--------|-------|---------|-----------|----------|
| Sigma | 3,338 | 1,819 | 2,888 | **86.5%** |
| Suricata | 67,229 | 51,476 | ~50% (file-based count) | ~50% |
| YARA | 4,321 | 4,321 | 0 | 0% — no native tagging |

**Correction — the earlier ~19% Sigma coverage figure.** This project
previously referenced a ~19% Sigma MITRE coverage figure. Before writing this
entry I searched the current repo (`CHANGES.md`, `SOC-3s-ARCHITECTURE-v3-final.md`)
and the full git history (`git log --all -S "19%"`, `git log --all -S
"securityonion-resources"`) for where that number was recorded — both came
back empty. It isn't written anywhere in this repo's committed history, so
there is no specific prior sentence to point at and correct. What can be
said with confidence: that figure, wherever it originated, was measured
against `/opt/so/conf/sigma/repos/securityonion-resources/` (26 rules — SO's
own IDH/monitoring detections), not the deployment's real ruleset. The actual
ruleset in use is `all_rules` (the full community set), against which
coverage is 86.5%, not ~19%. The corrected figure and its provenance are now
recorded in `SOC-3s-ARCHITECTURE-v3-final.md` §1 and §7 so it doesn't
resurface.

**Sigma tag parsing — four namespaces, not two.** `attack.t####[.###]` →
technique (normalized uppercase, e.g. `T1003.001`), `attack.g####` → ATT&CK
Group (`G0069`), `attack.s####` → ATT&CK Software (`S0002`), any other
`attack.*` → tactic (kept as a free-form string — SigmaHQ uses non-canonical
names like `attack.stealth`/`attack.defense-impairment` in practice, so
tactic strings are never validated against a hardcoded enum). Non-`attack.*`
tags (e.g. `detection.emerging-threats`) are filtered out entirely.

**Real Suricata parser bug fixed.** Phase B's metadata parser used a flat
`dict[str, str]`, so a rule with more than one `mitre_technique_id` entry
would silently keep only the last one. Rewritten to `dict[str, list[str]]`
(`setdefault(key, []).append(value)`), collecting all values per key. Same
regex-based extraction from the `metadata:` block as Phase B, unchanged — the
only difference is the input now comes from `so_detection.content` rather
than a line scanned out of `all.rules`.

**Return-shape reconciliation.** The rewrite spec's field-extraction list
(status/date/modified/logsource for Sigma; tactic names for Suricata) named
more fields than its literal return-dict listing enumerated. Resolved by
treating the extraction list as the floor and including all of it —
`tools/detection_rules.py::_parse_sigma` returns `status`, `date`,
`modified`, `logsource` beyond the documented shape, and `_parse_suricata`
returns `mitre_tactic_names` — documented inline in the code where each
extra field is added, rather than silently dropping fields that were
explicitly asked for.

**`tools/registry.py`'s `detection_rule_lookup` docstring updated** to
describe the new ES-backed lookup and its coverage numbers, and to state it
should be Agent 1's first call for MITRE mapping — confirmed with the user
before editing (this tool's docstring wasn't originally listed as in-scope
for this task).

**`prompts/perceiver.py`** updated to match: `detection_rule_lookup` is now
documented as the primary MITRE source (call it before
`qdrant_retrieve_mitre`, which is now the genuine fallback), with the real
coverage numbers instead of generic guidance.

**Removed:** all filesystem-walking/YAML-file-opening/`all.rules`-scanning
code from `tools/detection_rules.py`; `SIGMA_RULES_PATH` and
`SURICATA_RULES_PATH` from `config.py` (`Settings` fields, module-level
exports, and the `__main__` diagnostic print block).

**Not touched — user's responsibility, flagged not performed:**
- Removing `SIGMA_RULES_PATH`/`SURICATA_RULES_PATH` from `.env`.
- Removing the hourly rsync cron job on the agent-service VM that synced
  Sigma/Suricata rule files to this service — now fully obsolete, since
  nothing reads from the filesystem path anymore.
- Open item 3 from the Phase F entry above ("Suricata rules file staleness
  — no reload on a long-running process") is now moot: there is no longer a
  file to go stale. Superseded by this change, not separately resolved.

**Tests:** `tests/test_detection_rules.py` fully replaced (10 ES-mocked
tests: all four Sigma tag namespaces, non-standard tactic acceptance,
sub-technique normalization, Suricata with/without MITRE, YARA graceful
empty return, unknown `publicId`, ES timeout/error with no raise,
`source_engine` hint disagreeing with `so_detection.language` — language
wins, and a query-shape assertion). Uses the live-verified LSASS
credential-access rule (`ffa6861c-4461-4f59-8a41-578c39f3f23e`) as the
primary fixture.

`pytest tests/ -v`: **154/154 passing** (was 156/156 at the end of Phase F —
the 2 fewer tests reflects `test_detection_rules.py`'s full replacement, not
a coverage loss; the new file's 10 tests target the same contract with
ES-mock fixtures instead of filesystem fixtures).

Docs updated: `SOC-3s-ARCHITECTURE-v3-final.md` §1 (rename/rewrite history +
19% correction), §7 (full rewrite — ES query, per-engine parsing, coverage
table, return shape), §11 (tool inventory entry), §12 (tech-stack table, new
row for detection rule source).
