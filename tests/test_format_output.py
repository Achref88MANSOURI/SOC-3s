from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

from schemas import (
    CanonicalAlert,
    CorrelationResult,
    DeltaEvidence,
    DeltaVerdict,
    EvidencePackage,
    Host,
    InvestigationTraceEntry,
    Rule,
    TriageState,
    TriageVerdict,
)

from nodes.format_output import SEVERITY_TABLE, format_output


def _alert(alert_id: str = "test-001", host: str | None = None) -> CanonicalAlert:
    return CanonicalAlert(
        alert_id=alert_id,
        timestamp=datetime.now(timezone.utc),
        source_engine="suricata",
        investigation_profile="network_threat",
        rule=Rule(name="test", uuid="abc", native_severity=2),
        host=Host(hostname=host) if host else None,
    )


def test_severity_table_coverage():
    """Every likelihood × impact combination maps to a valid severity."""
    valid = {"low", "medium", "high", "critical"}
    for likelihood in ("unlikely", "possible", "likely", "near_certain"):
        for impact in ("minor", "moderate", "severe", "critical"):
            key = (likelihood, impact)
            assert key in SEVERITY_TABLE, f"Missing: {key}"
            assert SEVERITY_TABLE[key] in valid, f"Invalid severity: {SEVERITY_TABLE[key]}"


def test_dedup_path():
    state: TriageState = {
        "canonical_alert": _alert(),
        "correlation_result": CorrelationResult(action="deduplicated", mode="new", reason="dup window"),
        "mode": "new",
    }
    result = format_output(state)
    r = result["triage_result"]
    assert r.action == "deduplicated"
    assert r.alert_id == "test-001"
    assert r.verdict is None
    assert r.severity is None


def test_new_alert_path():
    state: TriageState = {
        "canonical_alert": _alert(),
        "correlation_result": CorrelationResult(action="new", mode="new", reason="no match"),
        "mode": "new",
        "triage_verdict": TriageVerdict(
            likelihood="likely",
            impact_if_true="severe",
            verdict="true_positive",
            reasoning="Evidence supports",
            recommended_action="create_case",
            summary="TP test",
        ),
        "evidence_package": EvidencePackage(),
    }
    result = format_output(state)
    r = result["triage_result"]
    assert r.action == "create_case"
    assert r.verdict == "true_positive"
    assert r.severity == "high"  # likely × severe = high
    assert r.likelihood == "likely"
    assert r.impact_if_true == "severe"


def test_new_low_severity():
    state: TriageState = {
        "canonical_alert": _alert(),
        "correlation_result": CorrelationResult(action="new", mode="new"),
        "mode": "new",
        "triage_verdict": TriageVerdict(
            likelihood="unlikely",
            impact_if_true="minor",
            verdict="false_positive",
            reasoning="No evidence",
            recommended_action="close_fp",
            summary="FP",
        ),
        "evidence_package": EvidencePackage(),
    }
    result = format_output(state)
    r = result["triage_result"]
    assert r.action == "close_fp"
    assert r.verdict == "false_positive"
    assert r.severity == "low"


def test_new_critical_severity():
    state: TriageState = {
        "canonical_alert": _alert(),
        "correlation_result": CorrelationResult(action="new", mode="new"),
        "mode": "new",
        "triage_verdict": TriageVerdict(
            likelihood="near_certain",
            impact_if_true="critical",
            verdict="true_positive",
            reasoning="Confirmed",
            recommended_action="create_case",
            summary="Critical TP",
        ),
        "evidence_package": EvidencePackage(),
    }
    result = format_output(state)
    assert result["triage_result"].severity == "critical"


def test_merge_quiet_path():
    state: TriageState = {
        "canonical_alert": _alert("alert-003"),
        "correlation_result": CorrelationResult(
            action="merge", mode="merge", merge_into_case="case-001",
        ),
        "mode": "merge",
        "delta_verdict": DeltaVerdict(
            severity_change="no_change",
            urgency="routine_merge",
            recommended_action="merge_quiet",
            reasoning="No material change",
        ),
        "delta_evidence": DeltaEvidence(),
        "evidence_package": None,
        "triage_verdict": None,
    }
    result = format_output(state)
    r = result["triage_result"]
    assert r.action == "merge_quiet"
    assert r.merge_into_case == "case-001"
    assert r.severity is None
    assert r.urgency == "routine_merge"


def test_merge_retier_path():
    state: TriageState = {
        "canonical_alert": _alert("alert-004"),
        "correlation_result": CorrelationResult(
            action="merge", mode="merge", merge_into_case="case-002",
        ),
        "mode": "merge",
        "delta_verdict": DeltaVerdict(
            severity_change="medium -> high",
            urgency="escalate",
            recommended_action="merge_and_retier",
            reasoning="New critical IOC",
        ),
        "delta_evidence": DeltaEvidence(),
        "evidence_package": None,
        "triage_verdict": None,
    }
    result = format_output(state)
    r = result["triage_result"]
    assert r.action == "merge_and_retier"
    assert r.severity == "high"
    assert r.severity_change == "medium -> high"
    assert r.urgency == "escalate"


def test_no_verdict_fallback():
    state: TriageState = {
        "canonical_alert": _alert(),
        "correlation_result": CorrelationResult(action="new", mode="new"),
        "mode": "new",
        "triage_verdict": None,
    }
    result = format_output(state)
    r = result["triage_result"]
    assert r.action == "needs_review"
    assert r.verdict == "needs_review"


def test_trace_in_output():
    trace = [
        InvestigationTraceEntry(
            tool="sigma_rule_lookup", params={"rule_uuid": "abc"}, result_summary="found"
        ),
    ]
    state: TriageState = {
        "canonical_alert": _alert(),
        "correlation_result": CorrelationResult(action="new", mode="new"),
        "mode": "new",
        "triage_verdict": TriageVerdict(
            likelihood="possible",
            impact_if_true="moderate",
            verdict="needs_review",
            reasoning="test",
            recommended_action="needs_review",
            summary="test",
        ),
        "evidence_package": EvidencePackage(investigation_trace=trace),
    }
    result = format_output(state)
    r = result["triage_result"]
    assert len(r.investigation_trace) == 1
    assert r.investigation_trace[0]["tool"] == "sigma_rule_lookup"


def test_new_alert_records_fp_outcome_when_host_present(tmp_path):
    db_path = str(tmp_path / "fp_events.db")
    state: TriageState = {
        "canonical_alert": _alert(host="srv-01"),
        "correlation_result": CorrelationResult(action="new", mode="new"),
        "mode": "new",
        "triage_verdict": TriageVerdict(
            likelihood="unlikely",
            impact_if_true="minor",
            verdict="false_positive",
            reasoning="No evidence",
            recommended_action="close_fp",
            summary="FP",
        ),
        "evidence_package": EvidencePackage(),
    }
    with patch("tools.fp_tracking.FP_DB_PATH", db_path):
        format_output(state)
        from tools.fp_tracking import get_fp_signal
        signal = get_fp_signal("abc", "srv-01")

    assert signal["short_term_total"] == 1
    assert signal["short_term_fp_rate"] == 1.0


def test_new_alert_skips_fp_recording_without_host(tmp_path):
    db_path = str(tmp_path / "fp_events.db")
    state: TriageState = {
        "canonical_alert": _alert(),  # no host — e.g. a network-only Suricata alert
        "correlation_result": CorrelationResult(action="new", mode="new"),
        "mode": "new",
        "triage_verdict": TriageVerdict(
            likelihood="likely",
            impact_if_true="severe",
            verdict="true_positive",
            reasoning="Evidence supports",
            recommended_action="create_case",
            summary="TP",
        ),
        "evidence_package": EvidencePackage(),
    }
    with patch("tools.fp_tracking.FP_DB_PATH", db_path):
        format_output(state)
        import os
        assert not os.path.exists(db_path)
