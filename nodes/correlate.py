from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from config import DEDUP_WINDOW_SECONDS, REDIS_URL
from schemas import CanonicalAlert, CorrelationResult, TriageState
from tools.sigma_rules import get_rule_source
from tools.thehive import search_open_cases

logger = logging.getLogger("agent-service.correlate")

MITRE_TECHNIQUE_RE = __import__("re").compile(r"(?:attack\.)?(T\d{4})", __import__("re").IGNORECASE)

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
    # Initial Access
    "T1078": "initial_access", "T1190": "initial_access", "T1133": "initial_access",
    "T1566": "initial_access", "T1189": "initial_access", "T1200": "initial_access",
    "T1091": "initial_access",
    # Execution
    "T1059": "execution", "T1204": "execution", "T1106": "execution",
    "T1569": "execution", "T1047": "execution", "T1053": "execution",
    # Persistence
    "T1547": "persistence", "T1098": "persistence", "T1136": "persistence",
    "T1505": "persistence", "T1543": "persistence",
    # Privilege Escalation
    "T1548": "privilege_escalation", "T1055": "privilege_escalation",
    "T1068": "privilege_escalation", "T1134": "privilege_escalation",
    # Defense Evasion
    "T1562": "defense_evasion", "T1070": "defense_evasion", "T1027": "defense_evasion",
    "T1036": "defense_evasion", "T1553": "defense_evasion",
    # Credential Access
    "T1555": "credential_access", "T1003": "credential_access",
    "T1558": "credential_access", "T1056": "credential_access", "T1110": "credential_access",
    # Discovery
    "T1087": "discovery", "T1083": "discovery", "T1069": "discovery",
    "T1016": "discovery", "T1033": "discovery", "T1049": "discovery",
    "T1018": "discovery", "T1012": "discovery", "T1482": "discovery",
    # Lateral Movement
    "T1021": "lateral_movement", "T1570": "lateral_movement",
    "T1550": "lateral_movement",
    # Collection
    "T1005": "collection", "T1074": "collection", "T1560": "collection",
    "T1114": "collection",
    # Command and Control
    "T1071": "command_and_control", "T1573": "command_and_control",
    "T1095": "command_and_control", "T1105": "command_and_control", "T1572": "command_and_control",
    # Exfiltration
    "T1048": "exfiltration", "T1567": "exfiltration", "T1020": "exfiltration",
    "T1537": "exfiltration",
    # Impact
    "T1486": "impact", "T1565": "impact", "T1489": "impact", "T1490": "impact",
}


def _tactic_index(tactic: str) -> int:
    try:
        return TACTIC_ORDER.index(tactic)
    except ValueError:
        return -1


def _extract_techniques_from_rule(alert: CanonicalAlert) -> set[str]:
    uuid = alert.rule.uuid if alert.rule else ""
    if not uuid:
        return set()
    rule = get_rule_source(uuid)
    if not rule or not rule.get("found"):
        return set()
    tags: list[str] = rule.get("tags", []) or []
    techniques: set[str] = set()
    for tag in tags:
        m = MITRE_TECHNIQUE_RE.search(tag)
        if m:
            techniques.add(m.group(1).upper())
    return techniques


def _extract_techniques_from_case_tags(tags: list[str]) -> set[str]:
    techniques: set[str] = set()
    for tag in tags:
        m = MITRE_TECHNIQUE_RE.search(tag)
        if m:
            techniques.add(m.group(1).upper())
    return techniques


def _tactics_from_techniques(techniques: set[str]) -> set[str]:
    tactics: set[str] = set()
    for t in techniques:
        tactic = TECHNIQUE_TO_TACTIC.get(t)
        if tactic:
            tactics.add(tactic)
    return tactics


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

    for t in alert_tactics:
        idx = _tactic_index(t)
        if idx > case_max_idx:
            return True

    return False


def correlate(state: TriageState) -> TriageState:
    alert = state.get("canonical_alert")
    if not alert:
        state["correlation_result"] = CorrelationResult(action="error", reason="No canonical_alert in state")
        state["mode"] = "new"
        return state

    alert = alert if isinstance(alert, CanonicalAlert) else CanonicalAlert(**alert)

    # Check 1: Redis fingerprint dedup
    dedup_result = _check_dedup(alert)
    if dedup_result.get("is_duplicate"):
        state["correlation_result"] = CorrelationResult(
            action="deduplicated",
            mode="new",
            reason=f"Duplicate alert (same fingerprint within {DEDUP_WINDOW_SECONDS}s window)",
        )
        state["mode"] = "new"
        return state

    # Check 2: Entity match (observables / host / user overlap)
    merge_case = _find_merge_candidate(alert)
    if merge_case:
        state["correlation_result"] = CorrelationResult(
            action="merge",
            mode="merge",
            merge_into_case=merge_case.get("case_id"),
            existing_case_context=merge_case,
            reason="Entity match with existing open case",
        )
        state["mode"] = "merge"
        state["existing_case_context"] = merge_case
        return state

    # Check 3: MITRE-adjacent story match (kill-chain progression)
    story_case = _find_story_match(alert)
    if story_case:
        state["correlation_result"] = CorrelationResult(
            action="merge",
            mode="merge",
            merge_into_case=story_case.get("case_id"),
            existing_case_context=story_case,
            reason="Kill-chain progression on related host",
        )
        state["mode"] = "merge"
        state["existing_case_context"] = story_case
        return state

    state["correlation_result"] = CorrelationResult(
        action="new",
        mode="new",
        reason="No duplicate, merge candidate, or story match found",
    )
    state["mode"] = "new"
    return state


def _check_dedup(alert: CanonicalAlert) -> dict:
    if not REDIS_URL:
        return {"is_duplicate": False}

    try:
        import redis as redis_lib
        fp_input = f"{alert.rule.uuid}:{alert.host.hostname if alert.host else ''}:{alert.user.name if alert.user else ''}"
        if alert.observables.external_ips:
            fp_input += ":" + ",".join(sorted(alert.observables.external_ips[:3]))

        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()
        r = redis_lib.from_url(REDIS_URL)
        key = f"dedup:{fingerprint}"
        existing = r.get(key)

        if existing:
            return {"is_duplicate": True, "fingerprint": fingerprint}

        r.setex(key, DEDUP_WINDOW_SECONDS, alert.alert_id)
        return {"is_duplicate": False, "fingerprint": fingerprint}
    except Exception:
        return {"is_duplicate": False}


def _find_merge_candidate(alert: CanonicalAlert) -> dict | None:
    observables = list(alert.observables.external_ips or [])
    observables.extend(alert.observables.domains or [])

    hostname = alert.host.hostname if alert.host else None
    username = alert.user.name if alert.user else None

    candidates = search_open_cases(
        observables=observables or None,
        host=hostname,
        user=username,
    )

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
        case_tags: list[str] = case.get("tags", []) or []
        case_techniques = _extract_techniques_from_case_tags(case_tags)
        if not case_techniques:
            continue

        if _is_kill_chain_progression(alert_techniques, case_techniques):
            logger.info(
                "Story match found: alert techniques=%s, case=%s, case_techniques=%s",
                alert_techniques, case.get("case_id"), case_techniques,
            )
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
