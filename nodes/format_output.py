from __future__ import annotations

from schemas import TriageState, TriageResult
from tools.fp_tracking import record_triage_outcome

SEVERITY_TABLE = {
    ("unlikely", "minor"): "low",
    ("unlikely", "moderate"): "low",
    ("unlikely", "severe"): "medium",
    ("unlikely", "critical"): "medium",
    ("possible", "minor"): "low",
    ("possible", "moderate"): "medium",
    ("possible", "severe"): "high",
    ("possible", "critical"): "high",
    ("likely", "minor"): "medium",
    ("likely", "moderate"): "high",
    ("likely", "severe"): "high",
    ("likely", "critical"): "critical",
    ("near_certain", "minor"): "medium",
    ("near_certain", "moderate"): "high",
    ("near_certain", "severe"): "critical",
    ("near_certain", "critical"): "critical",
}


def format_output(state: TriageState) -> TriageState:
    alert = state.get("canonical_alert")
    corr = state.get("correlation_result")
    verdict = state.get("triage_verdict")
    delta = state.get("delta_verdict")
    evidence = state.get("evidence_package")
    delta_evidence = state.get("delta_evidence")
    mode = state.get("mode", "new")

    alert_id = alert.alert_id if alert else ""

    if corr and corr.action == "deduplicated":
        state["triage_result"] = TriageResult(
            alert_id=alert_id,
            action="deduplicated",
            reasoning=corr.reason,
            summary="Alert was deduplicated — identical alert seen within dedup window.",
            correlation_result=corr.model_dump() if corr else None,
        )
        return state

    if mode == "merge" and delta:
        urgency = delta.urgency
        severity_change = delta.severity_change
        action = delta.recommended_action
        reasoning = delta.reasoning

        severity = None
        if severity_change and severity_change != "no_change":
            parts = severity_change.split("->")
            severity = parts[-1].strip() if len(parts) > 1 else None

        state["triage_result"] = TriageResult(
            alert_id=alert_id,
            action=action,
            verdict=None,
            severity=severity,
            likelihood=None,
            impact_if_true=None,
            mitre_mapping=[],
            reasoning=reasoning,
            summary=f"Merge assessment: {urgency}, scope change: {delta.scope_change}",
            merge_into_case=corr.merge_into_case if corr else None,
            severity_change=severity_change,
            urgency=urgency,
            evidence_package=delta_evidence.model_dump() if delta_evidence else {},
            investigation_trace=[t.model_dump() for t in (delta_evidence.investigation_trace if delta_evidence else [])],
            correlation_result=corr.model_dump() if corr else None,
        )
        return state

    if not verdict:
        state["triage_result"] = TriageResult(
            alert_id=alert_id,
            action="needs_review",
            verdict="needs_review",
            reasoning="No verdict produced by analysis node.",
            summary="Automated analysis failed — manual review required.",
            correlation_result=corr.model_dump() if corr else None,
        )
        return state

    severity = SEVERITY_TABLE.get((verdict.likelihood, verdict.impact_if_true), "medium")

    record_triage_outcome(
        rule_uuid=alert.rule.uuid if alert and alert.rule else "",
        host=alert.host.hostname if alert and alert.host else "",
        is_fp=verdict.verdict == "false_positive",
        verdict_confidence=verdict.likelihood,
    )

    state["triage_result"] = TriageResult(
        alert_id=alert_id,
        action=verdict.recommended_action,
        verdict=verdict.verdict,
        severity=severity,
        likelihood=verdict.likelihood,
        impact_if_true=verdict.impact_if_true,
        mitre_mapping=verdict.mitre_mapping,
        reasoning=verdict.reasoning,
        summary=verdict.summary,
        merge_into_case=corr.merge_into_case if corr else None,
        severity_change=None,
        urgency=None,
        evidence_package=evidence.model_dump() if evidence else {},
        investigation_trace=[t.model_dump() for t in (evidence.investigation_trace if evidence else [])],
        correlation_result=corr.model_dump() if corr else None,
    )

    return state
