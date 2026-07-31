from __future__ import annotations

from datetime import datetime, timezone

from schemas import CanonicalAlert, EvidencePackage, Rule, TriageState, TriageVerdict, DeltaVerdict
from nodes.analyze import _extract_json, _summarize_evidence


def test_extract_json_simple():
    assert _extract_json('{"a": 1}') == '{"a": 1}'


def test_extract_json_nested():
    text = '{"key": {"nested": [1, 2, 3]}}'
    assert _extract_json(text) == text


def test_extract_json_with_markdown():
    text = '```json\n{"a": 1}\n```'
    assert _extract_json(text) == '{"a": 1}'


def test_extract_json_with_text():
    text = 'Some text {"result": "ok"} trailing'
    assert _extract_json(text) == '{"result": "ok"}'


def test_extract_json_empty():
    assert _extract_json("") is None
    assert _extract_json("   ") is None


def test_extract_json_no_braces():
    assert _extract_json("hello world") is None


def test_extract_json_only_braces():
    assert _extract_json("{}") == "{}"


def test_summarize_evidence_full():
    ep = EvidencePackage(
        rule_context={"title": "test-rule", "severity": "high"},
        asset_context={"hostname": "srv-01", "criticality": "high"},
        threat_intel=[
            {"observable": "8.8.8.8", "type": "ip", "verdict": "malicious", "score": 90, "details": "bad", "analyzer": "vt"},
        ],
        temporal_context={"related_alerts_24h": [1, 2, 3, 4, 5], "host": "srv-01"},
        historical_context={"similar_past_cases": [1, 2]},
        investigation_gaps=["No process data"],
    )
    summary = _summarize_evidence(ep)
    assert summary["rule_context"]["title"] == "test-rule"
    assert summary["asset_context"]["hostname"] == "srv-01"
    assert len(summary["threat_intel_summary"]) == 1
    assert summary["threat_intel_summary"][0]["verdict"] == "malicious"
    assert summary["temporal_context"]["total_related_alerts"] == 5
    assert summary["historical_context"]["total_past_cases"] == 2
    assert "No process data" in summary["investigation_gaps"]


def test_summarize_evidence_empty():
    ep = EvidencePackage()
    summary = _summarize_evidence(ep)
    assert summary["rule_context"] == {}
    assert summary["threat_intel_summary"] == []
    assert summary["temporal_context"]["total_related_alerts"] == 0


def test_summarize_evidence_none():
    summary = _summarize_evidence(None)
    assert summary["rule_context"] == {}
    assert summary["threat_intel_summary"] == []


def test_summarize_evidence_dict():
    data = {
        "rule_context": {"title": "test"},
        "threat_intel": [{"observable": "1.2.3.4", "type": "ip", "verdict": "clean", "score": 5, "details": "", "analyzer": None}],
        "temporal_context": {"related_alerts_24h": [1]},
        "historical_context": {},
        "investigation_gaps": [],
    }
    summary = _summarize_evidence(data)
    assert summary["rule_context"]["title"] == "test"
    assert len(summary["threat_intel_summary"]) == 1


def test_extract_json_markdown_with_language():
    text = "```\n{\"key\": \"value\"}\n```"
    result = _extract_json(text)
    assert result is not None
    assert '"key"' in result


def test_extract_json_unclosed_brace():
    """Should return None for malformed JSON."""
    text = '{"key": "value"'
    assert _extract_json(text) is None
