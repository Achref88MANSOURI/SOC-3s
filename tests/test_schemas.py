from __future__ import annotations

from datetime import datetime, timezone

from schemas import (
    CanonicalAlert,
    CorrelationResult,
    DeltaEvidence,
    DeltaVerdict,
    EvidencePackage,
    HashBundle,
    Host,
    InvestigationTraceEntry,
    MitreMapping,
    Network,
    Observables,
    Process,
    Rule,
    TriageResult,
    TriageState,
    TriageVerdict,
    User,
)


def test_canonical_alert_minimal():
    alert = CanonicalAlert(
        alert_id="alert-001",
        timestamp=datetime.now(timezone.utc),
        source_engine="suricata",
        investigation_profile="network_threat",
        rule=Rule(name="test-rule", uuid="abc-123", native_severity=3),
    )
    assert alert.alert_id == "alert-001"
    assert alert.host is None
    assert alert.observables.external_ips == []
    assert alert.observables.hashes.md5 == []


def test_canonical_alert_full():
    alert = CanonicalAlert(
        alert_id="alert-002",
        timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
        source_engine="sigma",
        investigation_profile="endpoint_behavior",
        rule=Rule(name="win-login", uuid="xyz-789", native_severity=2),
        host=Host(hostname="srv-01", ip=["10.0.0.1"]),
        user=User(name="jdoe"),
        network=Network(src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443, protocol="TLS"),
        process=Process(pid=1234, name="powershell.exe"),
        observables=Observables(
            external_ips=["8.8.8.8"],
            domains=["evil.com"],
            hashes=HashBundle(sha256=["abc123def456"]),
        ),
    )
    assert alert.host.hostname == "srv-01"
    assert alert.network.dst_ip == "8.8.8.8"
    assert alert.process.name == "powershell.exe"
    assert "evil.com" in alert.observables.domains


def test_triage_result_new():
    r = TriageResult(
        alert_id="alert-001",
        action="create_case",
        verdict="true_positive",
        severity="high",
        likelihood="likely",
        impact_if_true="severe",
        mitre_mapping=[
            MitreMapping(tactic="execution", technique="T1059", confidence="high", basis="rule tag")
        ],
        reasoning="Evidence supports this.",
        summary="TP alert.",
    )
    assert r.action == "create_case"
    assert r.severity == "high"
    assert r.merge_into_case is None


def test_triage_result_dedup():
    r = TriageResult(
        alert_id="alert-001",
        action="deduplicated",
        reasoning="Duplicate within window",
    )
    assert r.verdict is None
    assert r.severity is None


def test_triage_result_merge():
    r = TriageResult(
        alert_id="alert-003",
        action="merge_quiet",
        merge_into_case="case-123",
        severity_change="no_change",
        urgency="routine_merge",
    )
    assert r.merge_into_case == "case-123"
    assert r.urgency == "routine_merge"


def test_correlation_result():
    r = CorrelationResult(action="merge", mode="merge", merge_into_case="case-001")
    assert r.action == "merge"
    assert r.mode == "merge"
    assert r.reason == ""  # default


def test_evidence_package_defaults():
    ep = EvidencePackage()
    assert ep.rule_context == {}
    assert ep.threat_intel == []
    assert ep.investigation_gaps == []
    assert ep.investigation_trace == []


def test_delta_evidence():
    de = DeltaEvidence(
        new_iocs=["8.8.8.8"],
        new_hosts=["host-b"],
        new_kill_chain_stages=["exfiltration"],
    )
    assert "8.8.8.8" in de.new_iocs
    assert "exfiltration" in de.new_kill_chain_stages


def test_triage_verdict():
    v = TriageVerdict(
        likelihood="likely",
        impact_if_true="critical",
        verdict="true_positive",
        reasoning="test",
        recommended_action="create_case",
        summary="summary",
    )
    assert v.likelihood == "likely"
    assert v.impact_if_true == "critical"
    assert v.recommended_action == "create_case"


def test_delta_verdict():
    v = DeltaVerdict(
        severity_change="medium -> high",
        urgency="escalate",
        recommended_action="merge_and_retier",
        reasoning="New evidence",
    )
    assert v.severity_change == "medium -> high"
    assert v.urgency == "escalate"


def test_triage_state_typed_dict():
    state: TriageState = {
        "mode": "new",
        "canonical_alert": None,
    }
    assert state["mode"] == "new"
    state["mode"] = "merge"
    assert state["mode"] == "merge"


def test_investigation_trace_entry():
    entry = InvestigationTraceEntry(tool="cortex_analyze", params={"type": "ip", "value": "8.8.8.8"})
    assert entry.tool == "cortex_analyze"
    assert entry.params["value"] == "8.8.8.8"
    assert entry.result_summary == ""
