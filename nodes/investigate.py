from __future__ import annotations

import json
import logging

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent

from config import settings
from prompts.investigator import build_prompt
from schemas import DeltaEvidence, EvidencePackage, InvestigationTraceEntry, TriageState
from tools.registry import INVESTIGATION_TOOLS

logger = logging.getLogger("agent-service.investigate")

_model = ChatOpenAI(
    base_url=settings.llm_base_url,
    api_key=settings.llm_api_key or "sk-no-auth",
    model=settings.llm_model,
    temperature=0.0,
)


def investigate(state: TriageState) -> TriageState:
    mode = state.get("mode", "new")
    alert = state.get("canonical_alert")
    if not alert:
        logger.error("No canonical_alert in state")
        return state

    profile = getattr(alert, "investigation_profile", "generic")
    system_prompt = build_prompt(profile, mode)
    max_calls = settings.max_tool_calls_new if mode == "new" else settings.max_tool_calls_merge

    agent = create_react_agent(
        model=_model,
        tools=INVESTIGATION_TOOLS,
        prompt=system_prompt,
    )

    alert_data = alert.model_dump() if hasattr(alert, "model_dump") else str(alert)
    human_parts = [f"Investigate this alert:\n{json.dumps(alert_data, indent=2, default=str)}"]

    existing_cortex_results = getattr(alert, "cortex_results", None) or []
    if existing_cortex_results:
        existing_dump = [
            r.model_dump() if hasattr(r, "model_dump") else r for r in existing_cortex_results
        ]
        human_parts.append(
            "\n\nExisting Cortex results already fetched from TheHive for this alert "
            "(do NOT call cortex_analyze on these observables again — only on ones "
            f"NOT in this list):\n{json.dumps(existing_dump, indent=2, default=str)}"
        )

    if mode == "merge" and state.get("existing_case_context"):
        human_parts.append(
            f"\n\nExisting case context:\n{json.dumps(state['existing_case_context'], indent=2, default=str)}"
        )

    try:
        result = agent.invoke(
            {"messages": [HumanMessage(content="\n".join(human_parts))]},
            {"recursion_limit": max_calls * 4 + 15},
        )
    except Exception as e:
        logger.error("ReAct agent failed: %s", str(e))
        return _fallback_state(state, mode, str(e), existing_cortex_results)

    messages = result.get("messages", [])
    trace = _extract_trace(messages)
    final_text = _get_final_text(messages)
    parsed = _try_parse_json(final_text)

    if parsed:
        logger.info("Agent produced valid JSON output")
        evidence_data = parsed
    else:
        logger.warning("Agent JSON unparseable, building from tool results instead")
        evidence_data = _build_from_tool_results(messages, trace)

    if mode == "new":
        threat_intel = _merge_cortex_results(
            _to_cortex_results(evidence_data.get("threat_intel", [])),
            existing_cortex_results,
        )
        state["evidence_package"] = EvidencePackage(
            rule_context=evidence_data.get("rule_context", {}),
            asset_context=evidence_data.get("asset_context", {}),
            threat_intel=threat_intel,
            temporal_context=evidence_data.get("temporal_context", {}),
            historical_context=evidence_data.get("historical_context", {}),
            investigation_gaps=evidence_data.get("investigation_gaps", []),
            investigation_trace=trace,
        )
        state["delta_evidence"] = None
    else:
        state["delta_evidence"] = DeltaEvidence(
            new_iocs=evidence_data.get("new_iocs", []),
            new_hosts=evidence_data.get("new_hosts", []),
            new_users=evidence_data.get("new_users", []),
            new_kill_chain_stages=evidence_data.get("new_kill_chain_stages", []),
            changed_ti_verdicts=evidence_data.get("changed_ti_verdicts", []),
            additional_context=evidence_data.get("additional_context", {}),
            investigation_gaps=evidence_data.get("investigation_gaps", []),
            investigation_trace=trace,
        )
        state["evidence_package"] = None

    return state


def _build_from_tool_results(messages: list, trace: list[InvestigationTraceEntry]) -> dict:
    """Build evidence package directly from tool call results, no LLM JSON required."""
    data: dict = {
        "rule_context": {},
        "asset_context": {},
        "threat_intel": [],
        "temporal_context": {},
        "historical_context": {},
        "investigation_gaps": ["Agent did not produce structured JSON; evidence extracted from tool results"],
    }

    for msg in messages:
        if getattr(msg, "type", None) != "tool":
            continue
        name = getattr(msg, "name", "")
        content = str(getattr(msg, "content", ""))

        parsed = _try_parse_json(content)
        if not parsed:
            continue

        if name == "itop_asset_lookup" and parsed.get("found"):
            data["asset_context"] = {
                "hostname": parsed.get("hostname", ""),
                "criticality": parsed.get("criticality", ""),
                "owner": parsed.get("contacts", ""),
                "department": parsed.get("organization", ""),
                "services": parsed.get("services", ""),
                "network_zone": parsed.get("network_zone", ""),
            }

        elif name == "cortex_analyze":
            entry = {
                "observable": parsed.get("observable", ""),
                "type": parsed.get("type", ""),
                "verdict": parsed.get("verdict", "unknown"),
                "score": parsed.get("score", 0),
                "details": str(parsed.get("details", ""))[:300],
                "analyzer": parsed.get("analyzer", "cortex"),
            }
            if entry not in data["threat_intel"]:
                data["threat_intel"].append(entry)

        elif name == "qdrant_retrieve" and isinstance(parsed, list):
            # Agent 2's qdrant_retrieve is cve/playbooks only as of Phase C —
            # MITRE search moved to Agent 1's qdrant_retrieve_mitre, so this is
            # never technique candidates despite the old key name it used to have.
            data["historical_context"]["qdrant_rag_results"] = parsed

        elif name == "elasticsearch_query" and isinstance(parsed, list):
            if not data["temporal_context"].get("related_alerts_same_host_24h"):
                data["temporal_context"]["related_alerts_same_host_24h"] = parsed[:10]
            else:
                existing = data["temporal_context"].get("related_alerts_same_host_24h", [])
                data["temporal_context"]["related_alerts_same_host_24h"] = (existing + parsed)[:10]

        elif name == "thehive_search_closed" and isinstance(parsed, list):
            if not data["historical_context"].get("similar_past_cases"):
                data["historical_context"]["similar_past_cases"] = parsed[:5]

    return data


def _coerce_score(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _to_cortex_results(items: list) -> list:
    from schemas import CortexResult
    results = []
    for item in items:
        if isinstance(item, dict):
            try:
                results.append(CortexResult(**item))
            except Exception:
                results.append(CortexResult(
                    observable=str(item.get("observable", "unknown")),
                    type=str(item.get("type", "unknown")),
                    verdict=str(item.get("verdict", "unknown")),
                    score=_coerce_score(item.get("score", 0)),
                    details=str(item),
                ))
        elif hasattr(item, "model_dump"):
            results.append(item)
    return results


def _merge_cortex_results(agent_threat_intel: list, existing_cortex_results: list) -> list:
    """Guarantee Agent 1's pre-fetched Cortex results survive into the final
    EvidencePackage even if the agent's JSON output doesn't echo them back —
    don't rely on the LLM to faithfully carry forward data it was only shown as
    context. Agent's own findings win on conflict (deduped by observable)."""
    seen = {r.observable for r in agent_threat_intel}
    merged = list(agent_threat_intel)
    for r in existing_cortex_results:
        if r.observable not in seen:
            merged.append(r)
            seen.add(r.observable)
    return merged


def _extract_trace(messages: list) -> list[InvestigationTraceEntry]:
    trace = []
    pending: dict[str, tuple[str, dict]] = {}

    for msg in messages:
        tool_calls = getattr(msg, "tool_calls", None)
        if tool_calls:
            for tc in tool_calls:
                tid = tc.get("id", "")
                pending[tid] = (tc.get("name", "unknown"), tc.get("args", {}))

        if getattr(msg, "type", None) == "tool":
            tid = getattr(msg, "tool_call_id", "")
            if tid in pending:
                name, args = pending.pop(tid)
                trace.append(InvestigationTraceEntry(
                    tool=name,
                    params=args,
                    result_summary=str(getattr(msg, "content", ""))[:200],
                ))
            else:
                trace.append(InvestigationTraceEntry(
                    tool=getattr(msg, "name", "tool"),
                    params={},
                    result_summary=str(getattr(msg, "content", ""))[:200],
                ))

    return trace


def _get_final_text(messages: list) -> str:
    for msg in reversed(messages):
        if getattr(msg, "type", None) == "ai" and msg.content and not getattr(msg, "tool_calls", None):
            return str(msg.content)
    return ""


def _try_parse_json(text: str) -> dict | list | None:
    """Tool results can be dict- or list-shaped (elasticsearch_query,
    qdrant_retrieve, thehive_search_closed all return lists). A naive
    find("{")/rfind("}") extraction — the original approach here — silently
    unwraps a list's first dict element instead of returning the list itself
    or None, since "[{...}]" still contains a valid {...} substring. Try a
    direct parse of the whole (fence-stripped) text first, which correctly
    preserves whichever shape the content actually is; only fall back to
    brace/bracket extraction for text with real surrounding prose."""
    text = text.strip()
    if not text:
        return None
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(l for l in lines if not l.strip().startswith("```")).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    brace_start = text.find("{")
    bracket_start = text.find("[")
    starts = [i for i in (brace_start, bracket_start) if i != -1]
    if not starts:
        return None
    start = min(starts)
    closer = "}" if text[start] == "{" else "]"
    end = text.rfind(closer)
    if end == -1 or end <= start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None


def _fallback_state(state: TriageState, mode: str, error: str, existing_cortex_results: list) -> TriageState:
    gaps = [f"Agent invocation failed: {error}"]
    if mode == "new":
        state["evidence_package"] = EvidencePackage(
            threat_intel=list(existing_cortex_results),
            investigation_gaps=gaps,
        )
        state["delta_evidence"] = None
    else:
        state["delta_evidence"] = DeltaEvidence(additional_context={}, investigation_gaps=gaps)
        state["evidence_package"] = None
    return state
