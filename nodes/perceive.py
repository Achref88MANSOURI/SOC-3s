from __future__ import annotations

import hashlib
import json
import logging
import re

from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from config import DEDUP_WINDOW_SECONDS, REDIS_URL, settings
from prompts.perceiver import build_prompt
from schemas import CanonicalAlert, CorrelationResult, MitreMapping, TriageState
from tools.detection_rules import get_rule_source
from tools.registry import PERCEPTION_TOOLS
from tools.thehive import search_open_cases

logger = logging.getLogger("agent-service.perceive")

_model = ChatOpenAI(
    base_url=settings.llm_base_url,
    api_key=settings.llm_api_key or "sk-no-auth",
    model=settings.llm_model,
    temperature=0.0,
)

PERCEPTION_MAX_TOOL_CALLS = 4

MITRE_TECHNIQUE_RE = re.compile(r"(?:attack\.)?(T\d{4})", re.IGNORECASE)

TACTIC_ORDER = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

TECHNIQUE_TO_TACTIC: dict[str, str] = {
    "T1078": "initial_access", "T1190": "initial_access", "T1133": "initial_access",
    "T1566": "initial_access", "T1189": "initial_access", "T1200": "initial_access",
    "T1091": "initial_access",
    "T1059": "execution", "T1204": "execution", "T1106": "execution",
    "T1569": "execution", "T1047": "execution", "T1053": "execution",
    "T1547": "persistence", "T1098": "persistence", "T1136": "persistence",
    "T1505": "persistence", "T1543": "persistence",
    "T1548": "privilege_escalation", "T1055": "privilege_escalation",
    "T1068": "privilege_escalation", "T1134": "privilege_escalation",
    "T1562": "defense_evasion", "T1070": "defense_evasion", "T1027": "defense_evasion",
    "T1036": "defense_evasion", "T1553": "defense_evasion",
    "T1555": "credential_access", "T1003": "credential_access",
    "T1558": "credential_access", "T1056": "credential_access", "T1110": "credential_access",
    "T1087": "discovery", "T1083": "discovery", "T1069": "discovery",
    "T1016": "discovery", "T1033": "discovery", "T1049": "discovery",
    "T1018": "discovery", "T1012": "discovery", "T1482": "discovery",
    "T1021": "lateral_movement", "T1570": "lateral_movement",
    "T1550": "lateral_movement",
    "T1005": "collection", "T1074": "collection", "T1560": "collection",
    "T1114": "collection",
    "T1071": "command_and_control", "T1573": "command_and_control",
    "T1095": "command_and_control", "T1105": "command_and_control", "T1572": "command_and_control",
    "T1048": "exfiltration", "T1567": "exfiltration", "T1020": "exfiltration",
    "T1537": "exfiltration",
    "T1486": "impact", "T1565": "impact", "T1489": "impact", "T1490": "impact",
}


def _tactic_index(tactic: str) -> int:
    try:
        return TACTIC_ORDER.index(tactic)
    except ValueError:
        return -1


def _tactics_from_techniques(techniques: set[str]) -> set[str]:
    return {TECHNIQUE_TO_TACTIC[t] for t in techniques if t in TECHNIQUE_TO_TACTIC}


def _is_kill_chain_progression(alert_techniques: set[str], case_techniques: set[str]) -> bool:
    if not alert_techniques or not case_techniques:
        return False
    alert_tactics = _tactics_from_techniques(alert_techniques)
    case_tactics = _tactics_from_techniques(case_techniques)
    if not alert_tactics or not case_tactics:
        return False
    case_max_idx = max((_tactic_index(t) for t in case_tactics), default=-1)
    if case_max_idx < 0:
        return False
    return any(_tactic_index(t) > case_max_idx for t in alert_tactics)


def gate0_dedup(state: TriageState) -> TriageState:
    """Pure Python, no LLM. Exact-repeat filter — runs before Agent 1.
    Redis is optional: if REDIS_URL is unset, this never reports a duplicate."""
    alert = state.get("canonical_alert")
    if not alert:
        return state
    alert = alert if isinstance(alert, CanonicalAlert) else CanonicalAlert(**alert)
    state["canonical_alert"] = alert

    if _check_dedup(alert):
        state["correlation_result"] = CorrelationResult(
            action="deduplicated",
            mode="new",
            reason=f"Duplicate alert (same fingerprint within {DEDUP_WINDOW_SECONDS}s window)",
        )
        state["mode"] = "new"
    return state


def _check_dedup(alert: CanonicalAlert) -> bool:
    if not REDIS_URL:
        return False
    try:
        import redis as redis_lib
        fp_input = f"{alert.rule.uuid}:{alert.host.hostname if alert.host else ''}"
        if alert.observables.external_ips:
            fp_input += ":" + ",".join(sorted(alert.observables.external_ips[:3]))
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()
        r = redis_lib.from_url(REDIS_URL)
        key = f"dedup:{fingerprint}"
        if r.get(key):
            return True
        r.setex(key, DEDUP_WINDOW_SECONDS, alert.alert_id)
        return False
    except Exception:
        return False


def perceive(state: TriageState) -> TriageState:
    """Agent 1 — LLM ReAct loop. MITRE mapping + case correlation. Falls back to
    deterministic entity/kill-chain matching if the agent fails or its output
    doesn't parse (every LLM-facing node must degrade to a safe state, never 500)."""
    corr = state.get("correlation_result")
    if corr and corr.action == "deduplicated":
        return state  # gate0 already short-circuited this alert

    alert = state.get("canonical_alert")
    if not alert:
        logger.error("No canonical_alert in state")
        return state
    alert = alert if isinstance(alert, CanonicalAlert) else CanonicalAlert(**alert)

    agent = create_react_agent(
        model=_model,
        tools=PERCEPTION_TOOLS,
        prompt=build_prompt(),
    )

    human_content = f"Perceive and correlate this alert:\n{json.dumps(alert.model_dump(), indent=2, default=str)}"

    try:
        result = agent.invoke(
            {"messages": [HumanMessage(content=human_content)]},
            {"recursion_limit": PERCEPTION_MAX_TOOL_CALLS * 4 + 15},
        )
    except Exception as e:
        logger.error("Perceive ReAct agent failed: %s", str(e))
        return _fallback_deterministic(state, alert)

    final_text = _get_final_text(result.get("messages", []))
    parsed = _try_parse_json(final_text)

    if not parsed:
        logger.warning("Perceive agent JSON unparseable, falling back to deterministic correlation")
        return _fallback_deterministic(state, alert)

    return _apply_parsed_result(state, parsed)


def _apply_parsed_result(state: TriageState, parsed: dict) -> TriageState:
    mitre_mapping = [
        MitreMapping(**m) for m in parsed.get("mitre_mapping", []) if isinstance(m, dict)
    ]

    corr_data = parsed.get("correlation_result") or {}
    correlation_result = CorrelationResult(
        action=corr_data.get("action", "new"),
        mode=corr_data.get("mode", "new"),
        merge_into_case=corr_data.get("merge_into_case"),
        existing_case_context=corr_data.get("existing_case_context"),
        reason=corr_data.get("reason", ""),
        confidence=corr_data.get("confidence", "medium"),
    )

    state["mitre_mapping"] = mitre_mapping
    state["correlation_result"] = correlation_result
    state["mode"] = correlation_result.mode
    if correlation_result.action == "merge":
        state["existing_case_context"] = correlation_result.existing_case_context
    return state


def _fallback_deterministic(state: TriageState, alert: CanonicalAlert) -> TriageState:
    """Non-LLM safety net: the same entity-match / kill-chain logic the old
    correlate.py used, minus MITRE mapping (that genuinely needs the LLM — an
    empty mapping plus a gap note is the safe degraded state, not a guess)."""
    merge_case = _find_merge_candidate(alert)
    if merge_case:
        state["mitre_mapping"] = []
        state["correlation_result"] = CorrelationResult(
            action="merge",
            mode="merge",
            merge_into_case=merge_case.get("case_id"),
            existing_case_context=merge_case,
            reason="Entity match with existing open case (deterministic fallback — agent output unavailable)",
            confidence="medium",
        )
        state["mode"] = "merge"
        state["existing_case_context"] = merge_case
        return state

    story_case = _find_story_match(alert)
    if story_case:
        state["mitre_mapping"] = []
        state["correlation_result"] = CorrelationResult(
            action="merge",
            mode="merge",
            merge_into_case=story_case.get("case_id"),
            existing_case_context=story_case,
            reason="Kill-chain progression on related host (deterministic fallback — agent output unavailable)",
            confidence="medium",
        )
        state["mode"] = "merge"
        state["existing_case_context"] = story_case
        return state

    state["mitre_mapping"] = []
    state["correlation_result"] = CorrelationResult(
        action="new",
        mode="new",
        reason="No duplicate, merge candidate, or story match found (deterministic fallback)",
        confidence="medium",
    )
    state["mode"] = "new"
    return state


def _find_merge_candidate(alert: CanonicalAlert) -> dict | None:
    observables = list(alert.observables.external_ips or [])
    observables.extend(alert.observables.domains or [])

    hostname = alert.host.hostname if alert.host else None
    username = alert.user.name if alert.user else None

    candidates = search_open_cases(observables=observables or None, host=hostname, user=username)
    if not candidates:
        return None

    best = candidates[0]
    return {
        "case_id": best.get("case_id"),
        "title": best.get("title", ""),
        "severity": best.get("severity", 2),
        "status": best.get("status", ""),
        "tags": best.get("tags", []),
        "description": best.get("description", ""),
        "host": best.get("host", hostname or ""),
        "user": best.get("user", username or ""),
        "observables": best.get("observables", []),
        "created_at": best.get("created_at", ""),
    }


def _find_story_match(alert: CanonicalAlert) -> dict | None:
    hostname = alert.host.hostname if alert.host else None
    if not hostname:
        return None

    alert_techniques = _extract_techniques_from_rule(alert)
    if not alert_techniques:
        return None

    candidates = search_open_cases(host=hostname)
    if not candidates:
        return None

    for case in candidates:
        case_techniques = _extract_techniques_from_tags(case.get("tags", []) or [])
        if not case_techniques:
            continue
        if _is_kill_chain_progression(alert_techniques, case_techniques):
            return {
                "case_id": case.get("case_id"),
                "title": case.get("title", ""),
                "severity": case.get("severity", 2),
                "status": case.get("status", ""),
                "tags": case.get("tags", []),
                "description": case.get("description", ""),
                "host": hostname,
                "user": case.get("user", ""),
                "observables": case.get("observables", []),
                "created_at": case.get("created_at", ""),
            }
    return None


def _extract_techniques_from_rule(alert: CanonicalAlert) -> set[str]:
    uuid = alert.rule.uuid if alert.rule else ""
    if not uuid:
        return set()
    # source_engine hint avoids the full Sigma-then-Suricata-then-YARA fallback
    # chain when we already know which engine fired. get_rule_source() returns
    # "mitre_attack" in both the Sigma ("attack.txxxx" tag strings) and
    # Suricata (bare "Txxxx" IDs from metadata) shapes — MITRE_TECHNIQUE_RE
    # below matches both forms, so no per-engine branching is needed here.
    rule = get_rule_source(uuid, alert.source_engine)
    if not rule or not rule.get("found"):
        return set()
    return _extract_techniques_from_tags(rule.get("mitre_attack", []) or [])


def _extract_techniques_from_tags(tags: list[str]) -> set[str]:
    techniques: set[str] = set()
    for tag in tags:
        m = MITRE_TECHNIQUE_RE.search(tag)
        if m:
            techniques.add(m.group(1).upper())
    return techniques


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
