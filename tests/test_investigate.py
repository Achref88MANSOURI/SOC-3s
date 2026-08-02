from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from schemas import CanonicalAlert, CortexResult, Rule, TriageState
from nodes.investigate import (
    _build_from_tool_results,
    _extract_trace,
    _get_final_text,
    _merge_cortex_results,
    _to_cortex_results,
    _try_parse_json,
    investigate,
)


def _alert(cortex_results=None) -> CanonicalAlert:
    return CanonicalAlert(
        alert_id="test-001",
        timestamp=datetime.now(timezone.utc),
        source_engine="sigma",
        investigation_profile="endpoint_behavior",
        rule=Rule(name="test-rule", uuid="uuid-abc", native_severity=2),
        cortex_results=cortex_results or [],
    )


class _FakeMsg:
    def __init__(self, type_, content, tool_calls=None, name=None, tool_call_id=None):
        self.type = type_
        self.content = content
        self.tool_calls = tool_calls
        self.name = name
        self.tool_call_id = tool_call_id


def _cortex_result(observable, verdict="malicious", analyzer="VirusTotal"):
    return CortexResult(observable=observable, type="hash", verdict=verdict, score=90, details="d", analyzer=analyzer)


def test_try_parse_json_simple():
    assert _try_parse_json('{"a": 1}') == {"a": 1}


def test_try_parse_json_with_markdown():
    assert _try_parse_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_try_parse_json_empty():
    assert _try_parse_json("") is None


def test_try_parse_json_invalid():
    assert _try_parse_json("not json") is None


def test_to_cortex_results_from_dicts():
    items = [{"observable": "8.8.8.8", "type": "ip", "verdict": "clean", "score": 5, "details": "", "analyzer": "vt"}]
    results = _to_cortex_results(items)
    assert len(results) == 1
    assert results[0].observable == "8.8.8.8"


def test_to_cortex_results_malformed_dict_falls_back():
    items = [{"observable": "8.8.8.8", "score": "not-an-int"}]
    results = _to_cortex_results(items)
    assert len(results) == 1
    assert results[0].verdict == "unknown"


def test_merge_cortex_results_dedupes_by_observable():
    agent_ti = [_cortex_result("1.1.1.1", verdict="clean")]
    existing = [_cortex_result("1.1.1.1", verdict="malicious"), _cortex_result("2.2.2.2")]
    merged = _merge_cortex_results(agent_ti, existing)
    assert len(merged) == 2
    obs_map = {r.observable: r for r in merged}
    assert obs_map["1.1.1.1"].verdict == "clean"  # agent's own finding wins
    assert "2.2.2.2" in obs_map


def test_merge_cortex_results_empty_agent_output():
    existing = [_cortex_result("1.1.1.1")]
    merged = _merge_cortex_results([], existing)
    assert len(merged) == 1
    assert merged[0].observable == "1.1.1.1"


def test_build_from_tool_results_buckets_sigma_and_cortex():
    messages = [
        _FakeMsg("tool", json.dumps({"found": True, "description": "d", "tags": ["attack.t1059"], "level": "high"}), name="sigma_rule_lookup"),
        _FakeMsg("tool", json.dumps({"observable": "1.2.3.4", "type": "ip", "verdict": "malicious", "score": 90, "analyzer": "vt"}), name="cortex_analyze"),
    ]
    data = _build_from_tool_results(messages, [])
    assert data["rule_context"]["description"] == "d"
    assert data["threat_intel"][0]["observable"] == "1.2.3.4"
    assert "structured JSON" in data["investigation_gaps"][0]


def test_extract_trace_pairs_calls_with_results():
    messages = [
        _FakeMsg("ai", "", tool_calls=[{"id": "1", "name": "sigma_rule_lookup", "args": {"rule_uuid": "abc"}}]),
        _FakeMsg("tool", "result content", tool_call_id="1"),
    ]
    trace = _extract_trace(messages)
    assert len(trace) == 1
    assert trace[0].tool == "sigma_rule_lookup"
    assert trace[0].params == {"rule_uuid": "abc"}


def test_get_final_text_returns_last_non_tool_call_ai_message():
    messages = [
        _FakeMsg("ai", "", tool_calls=[{"id": "1"}]),
        _FakeMsg("tool", "x", tool_call_id="1"),
        _FakeMsg("ai", '{"final": true}'),
    ]
    assert _get_final_text(messages) == '{"final": true}'


@patch("nodes.investigate.create_react_agent")
def test_investigate_new_mode_parses_json(mock_create_agent):
    fake_agent = MagicMock()
    output = {
        "rule_context": {"description": "d"},
        "asset_context": {},
        "threat_intel": [],
        "temporal_context": {},
        "historical_context": {},
        "investigation_gaps": [],
    }
    fake_agent.invoke.return_value = {"messages": [_FakeMsg("ai", json.dumps(output))]}
    mock_create_agent.return_value = fake_agent

    state: TriageState = {"mode": "new", "canonical_alert": _alert()}
    result = investigate(state)

    assert result["evidence_package"].rule_context["description"] == "d"
    assert result["delta_evidence"] is None


@patch("nodes.investigate.create_react_agent")
def test_investigate_merge_mode_parses_json(mock_create_agent):
    fake_agent = MagicMock()
    output = {
        "new_iocs": ["1.1.1.1"],
        "new_hosts": [],
        "new_users": [],
        "new_kill_chain_stages": [],
        "changed_ti_verdicts": [],
        "additional_context": {},
        "investigation_gaps": [],
    }
    fake_agent.invoke.return_value = {"messages": [_FakeMsg("ai", json.dumps(output))]}
    mock_create_agent.return_value = fake_agent

    state: TriageState = {"mode": "merge", "canonical_alert": _alert(), "existing_case_context": {"case_id": "c-1"}}
    result = investigate(state)

    assert result["delta_evidence"].new_iocs == ["1.1.1.1"]
    assert result["evidence_package"] is None


@patch("nodes.investigate.create_react_agent")
def test_investigate_falls_back_to_tool_trace_on_unparseable_json(mock_create_agent):
    fake_agent = MagicMock()
    fake_agent.invoke.return_value = {
        "messages": [
            _FakeMsg("ai", "", tool_calls=[{"id": "1", "name": "sigma_rule_lookup", "args": {"rule_uuid": "uuid-abc"}}]),
            _FakeMsg("tool", json.dumps({"found": True, "description": "fp desc"}), name="sigma_rule_lookup", tool_call_id="1"),
            _FakeMsg("ai", "not valid json"),
        ]
    }
    mock_create_agent.return_value = fake_agent

    state: TriageState = {"mode": "new", "canonical_alert": _alert()}
    result = investigate(state)

    assert result["evidence_package"].rule_context["description"] == "fp desc"
    assert "structured JSON" in result["evidence_package"].investigation_gaps[0]


@patch("nodes.investigate.create_react_agent")
def test_investigate_preserves_existing_cortex_results_through_merge(mock_create_agent):
    fake_agent = MagicMock()
    output = {
        "rule_context": {}, "asset_context": {},
        "threat_intel": [{"observable": "new-hash", "type": "hash", "verdict": "malicious", "score": 90, "details": "", "analyzer": "vt"}],
        "temporal_context": {}, "historical_context": {}, "investigation_gaps": [],
    }
    fake_agent.invoke.return_value = {"messages": [_FakeMsg("ai", json.dumps(output))]}
    mock_create_agent.return_value = fake_agent

    alert = _alert(cortex_results=[_cortex_result("old-hash")])
    state: TriageState = {"mode": "new", "canonical_alert": alert}
    result = investigate(state)

    observables = {r.observable for r in result["evidence_package"].threat_intel}
    assert observables == {"new-hash", "old-hash"}


@patch("nodes.investigate.create_react_agent")
def test_investigate_agent_exception_falls_back_with_existing_cortex_results(mock_create_agent):
    fake_agent = MagicMock()
    fake_agent.invoke.side_effect = RuntimeError("LLM unreachable")
    mock_create_agent.return_value = fake_agent

    alert = _alert(cortex_results=[_cortex_result("old-hash")])
    state: TriageState = {"mode": "new", "canonical_alert": alert}
    result = investigate(state)

    assert result["evidence_package"].threat_intel[0].observable == "old-hash"
    assert "Agent invocation failed" in result["evidence_package"].investigation_gaps[0]


def test_investigate_no_alert_is_noop():
    state: TriageState = {"mode": "new"}
    result = investigate(state)
    assert result.get("evidence_package") is None
