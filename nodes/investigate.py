from __future__ import annotations

import json
import logging

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent

from config import settings
from prompts.investigator import build_prompt
from schemas import DeltaEvidence, EvidencePackage, InvestigationTraceEntry, TriageState
from tools.registry import TOOLS

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
        tools=TOOLS,
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

        if name == "sigma_rule_lookup":
            data["rule_context"] = {
                "description": parsed.get("description", parsed.get("error", "")),
                "detection_logic": parsed.get("detection_logic", ""),
                "known_fp_conditions": parsed.get("falsepositives", []) if isinstance(parsed.get("falsepositives"), list) else [parsed.get("falsepositives", "")],
                "mitre_tags_from_source": parsed.get("tags", []) if isinstance(parsed.get("tags"), list) else [parsed.get("tags", "")],
                "severity_from_source": parsed.get("level", ""),
            }

        elif name == "itop_asset_lookup" and parsed.get("found"):
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
            data["historical_context"]["mitre_candidates_from_rag"] = parsed

        elif name == "elasticsearch_query" and isinstance(parsed, list):
            if not data["temporal_context"].get("related_alerts_same_host_24h"):
                data["temporal_context"]["related_alerts_same_host_24h"] = parsed[:10]
            else:
                existing = data["temporal_context"].get("related_alerts_same_host_24h", [])
                data["temporal_context"]["related_alerts_same_host_24h"] = (existing + parsed)[:10]

        elif name == "thehive_search" and isinstance(parsed, list):
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


def _try_parse_json(text: str) -> dict | None:
    text = text.strip()
    if not text:
        return None
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(l for l in lines if not l.strip().startswith("```")).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return None
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
