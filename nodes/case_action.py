from __future__ import annotations

from schemas import TriageResult
from tools.thehive import (
    add_alert_comment,
    add_case_comment,
    merge_alert_into_case,
    promote_alert_to_case,
    update_alert_status,
    update_case,
)

_SEVERITY_TO_THEHIVE = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def execute_case_action(triage_result: TriageResult, approved: bool) -> dict:
    """Post-approval TheHive write path. NOT part of the automatic graph — n8n
    currently performs case actions itself based on TriageResult.action; this is
    the future path once an analyst has explicitly reviewed and approved a
    verdict. All TheHive operations are direct REST (tools/thehive.py), not
    TheHive MCP — see SOC-3s-ARCHITECTURE-v2.md §17 Decision 5 (BETA, known
    prompt-injection risk, TheHive 5.5+ requirement unconfirmed)."""
    if not approved:
        raise ValueError("Case action requires explicit analyst approval")

    action = triage_result.action

    if action == "create_case":
        return _create_case(triage_result)
    elif action == "close_fp":
        return _close_fp(triage_result)
    elif action == "merge_quiet":
        return _merge_quiet(triage_result)
    elif action == "merge_and_retier":
        return _merge_and_retier(triage_result)
    else:
        return {"status": "skipped", "action": action, "reason": f"No case action defined for action '{action}'"}


def _mitre_tags(triage_result: TriageResult) -> list[str]:
    return [f"{m.tactic}:{m.technique}" for m in triage_result.mitre_mapping]


def _case_title(triage_result: TriageResult) -> str:
    severity_label = (triage_result.severity or "unknown").upper()
    if triage_result.summary:
        return f"[{severity_label}] {triage_result.summary[:80]}"
    return f"[{severity_label}] Alert {triage_result.alert_id}"


def _investigation_summary(triage_result: TriageResult) -> str:
    return f"{triage_result.summary}\n\nReasoning: {triage_result.reasoning}"


def _delta_summary(triage_result: TriageResult) -> str:
    return f"{triage_result.summary}\n\nReasoning: {triage_result.reasoning}"


def _create_case(triage_result: TriageResult) -> dict:
    alert_id = triage_result.alert_id
    case = promote_alert_to_case(alert_id)
    if not case:
        return {"status": "error", "action": "create_case", "reason": "Failed to promote alert to case"}

    case_id = case.get("_id") or case.get("id")
    severity = _SEVERITY_TO_THEHIVE.get(triage_result.severity, 2)
    update_case(case_id, title=_case_title(triage_result), severity=severity, tags=_mitre_tags(triage_result))
    add_case_comment(case_id, _investigation_summary(triage_result))

    return {"status": "ok", "action": "create_case", "case_id": case_id}


def _close_fp(triage_result: TriageResult) -> dict:
    alert_id = triage_result.alert_id
    # "Ignored" is TheHive 5's built-in status for false positive / not
    # actionable alerts — verified against the live 5.6.1 instance's UI, which
    # has no custom statuses configured (only New, Updated, Ignored, Imported).
    update_alert_status(alert_id, "Ignored")
    add_alert_comment(alert_id, triage_result.reasoning or triage_result.summary)

    return {"status": "ok", "action": "close_fp", "alert_id": alert_id}


def _merge_quiet(triage_result: TriageResult) -> dict:
    alert_id = triage_result.alert_id
    case_id = triage_result.merge_into_case
    if not case_id:
        return {"status": "error", "action": "merge_quiet", "reason": "No merge_into_case on TriageResult"}

    merge_alert_into_case(alert_id, case_id)
    add_case_comment(case_id, _delta_summary(triage_result))

    return {"status": "ok", "action": "merge_quiet", "case_id": case_id}


def _merge_and_retier(triage_result: TriageResult) -> dict:
    alert_id = triage_result.alert_id
    case_id = triage_result.merge_into_case
    if not case_id:
        return {"status": "error", "action": "merge_and_retier", "reason": "No merge_into_case on TriageResult"}

    merge_alert_into_case(alert_id, case_id)
    severity = _SEVERITY_TO_THEHIVE.get(triage_result.severity, 2)
    update_case(case_id, severity=severity)
    add_case_comment(case_id, _delta_summary(triage_result))

    return {
        "status": "ok",
        "action": "merge_and_retier",
        "case_id": case_id,
        "urgent_notification_required": True,
    }
