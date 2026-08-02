# SOC-3s Agent Service — Change Log
Last updated: 2026-08-02

## Phases completed
- [x] Phase 1 — Bug fixes (already resolved by a prior uncommitted session — see below)
- [x] Phase 2 — New input contract
- [x] Phase 3 — Agent 1 (perceive.py)
- [x] Phase 4 — Cortex integration (attempted via cortex-mcp, reverted to direct REST — see below)
- [x] Phase 5 — Agent 2 structured output
- [ ] Phase 6 — Agent 3 two-pass MITRE
- [ ] Phase 7 — Format output fixes + end-to-end
- [ ] Phase 8 — Case action stub
- [ ] Phase 9 — n8n integration notes
- [ ] Phase 10 — Tests

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

## Files created
| File | Purpose | Phase |
|------|---------|-------|
| alert_builder.py | `build_canonical_alert(raw_alert, hive_alert, asset_context, thehive_alert_id)` — deterministic, best-effort CanonicalAlert assembly from n8n's slim payload + TheHive fetch + iTop context. Includes the mandatory observable dataType sanity check (URL mis-tagged as domain). Fields it can't confidently parse (user, network, most file/process cases) are left `None` — that's intentional, Agent 1 (Phase 3) fills gaps with LLM reasoning. | 2 |
| tests/test_alert_builder.py | 5 tests: rule/host/process parsing from description text, URL-mis-tagged-as-domain correction, Cortex report mapping from TheHive fetch, missing-hive_alert handling, fallback behavior when description has no structured fields | 2 |
| prompts/perceiver.py | `build_prompt()` — Agent 1's system prompt: MITRE mapping + case correlation reasoning (entity match strength, kill-chain progression), 3-tool budget-4 ReAct loop, `{mitre_mapping, correlation_result}` JSON output contract. No `mode` parameter — Agent 1 *decides* mode, it doesn't receive it (the architecture doc's file-tree table says `build_prompt(mode)` for this file, but that's inconsistent with Agent 1's actual role per §6; built as `build_prompt()` instead). | 3 |
| nodes/perceive.py | Replaces `nodes/correlate.py`. `gate0_dedup()` — pure Python Redis fingerprint check, ported verbatim from `correlate.py`. `perceive()` — Agent 1: a `create_react_agent` ReAct loop over `PERCEPTION_TOOLS` (`sigma_rule_lookup`, `qdrant_retrieve_mitre`, `thehive_open_cases`) producing `mitre_mapping` + `correlation_result`. On agent exception or unparseable JSON, falls back to `_fallback_deterministic()` — the same entity-match/kill-chain logic `correlate.py` used (ported, not imported, since `correlate.py` is retired), minus MITRE mapping (an empty list + a "fallback" reason is the safe degraded state, not a guess). Preserves the "every LLM-facing node has a non-LLM fallback" invariant. | 3 |
| tests/test_perceive.py | 15 tests: ported kill-chain/tactic-index unit tests from `test_correlate.py`; `gate0_dedup` duplicate/no-duplicate/no-alert cases; `perceive()` with a mocked `create_react_agent` for new-mode and merge-mode JSON parsing, unparseable-JSON fallback, agent-`.invoke()`-exception fallback (mocking `.invoke()` to raise, not `create_react_agent()` itself — construction isn't try/except-wrapped, matching `investigate.py`'s existing pattern), already-deduplicated short-circuit, and missing-alert no-op | 3 |
| tests/test_investigate.py | 17 tests, first-ever coverage for `investigate.py`: `_try_parse_json` edge cases, `_to_cortex_results` (including the malformed-score fallback bug found and fixed in this phase), `_merge_cortex_results` dedup behavior, `_build_from_tool_results` bucketing, `_extract_trace` call/result pairing, `_get_final_text`, and `investigate()` end-to-end for new-mode JSON parse, merge-mode JSON parse, unparseable-JSON fallback, existing-cortex-results survival through both the normal and agent-exception paths, and no-alert no-op | 5 |

## Files deleted / renamed
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
- [x] ~~Whether agent-service runs on the same host as cortex-mcp~~ — resolved: it doesn't (172.20.24.224 vs 172.20.24.221), which is exactly why Phase 4 was reverted.

## Test results
| Phase | Tests run | Pass | Fail | Notes |
|-------|----------|------|------|-------|
| 1 (baseline) | `python3 -m pytest tests/ -q` | 71 | 0 | Before any code changes |
| 2 | `python3 -m pytest tests/ -q` | 76 | 0 | +5 new tests in `test_alert_builder.py`; also re-ran `test.sh`'s syntax-check and import/route-registration checks manually (no `requirements-dev.txt` yet) — both passed |
| 3 | `python3 -m pytest tests/ -q` | 79 | 0 | `test_correlate.py` (11 tests) retired, `test_perceive.py` (15 tests) added, `test_graph.py` rewritten (7 tests) — net +3. Syntax check, import check, and `graph.nodes` inspection (`gate0`, `perceive`, `investigate`, `analyze`, `format_output` all present) also passed manually. |
| 4 (build) | `python3 -m pytest tests/ -q` | 93 | 0 | +14 new tests in `test_cortex_mcp.py` (12) plus incidental coverage. `langchain-mcp-adapters` + `mcp==1.29.0` installed to make these imports/tests possible. |
| 4 (revert) | `python3 -m pytest tests/ -q` | 79 | 0 | Back to the Phase 3 count — `test_cortex_mcp.py` deleted. `git diff` against the pre-Phase-4 commit confirms `config.py`/`tools/registry.py`/`requirements.txt` are byte-identical; `prompts/investigator.py` retains 2 intentional discipline-rule lines (see Files modified). `langchain-mcp-adapters`/`mcp` uninstalled from the environment. |
| 5 | `python3 -m pytest tests/ -q` | 96 | 0 | +17 new tests in `test_investigate.py`. One test (`test_to_cortex_results_malformed_dict_falls_back`) initially failed against real (pre-existing) code, exposing the `_coerce_score` bug — fixed, then green. Syntax check and import check also passed manually. |
