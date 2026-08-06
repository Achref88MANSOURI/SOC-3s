from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from schemas import CanonicalAlert, Host, Rule, TriageState
from nodes.perceive import (
    _is_kill_chain_progression,
    _tactic_index,
    _tactics_from_techniques,
    gate0_dedup,
    perceive,
)


def _alert(rule_uuid: str = "uuid-abc", hostname: str | None = "srv-01") -> CanonicalAlert:
    return CanonicalAlert(
        alert_id="test-001",
        timestamp=datetime.now(timezone.utc),
        source_engine="suricata",
        investigation_profile="network_threat",
        rule=Rule(name="test-rule", uuid=rule_uuid, native_severity=2),
        host=Host(hostname=hostname) if hostname else None,
    )


class _FakeMsg:
    def __init__(self, type_, content, tool_calls=None):
        self.type = type_
        self.content = content
        self.tool_calls = tool_calls


def test_tactic_index():
    assert _tactic_index("initial_access") == 2
    assert _tactic_index("execution") == 3
    assert _tactic_index("unknown_tactic") == -1


def test_tactics_from_techniques():
    tactics = _tactics_from_techniques({"T1566", "T1059"})
    assert "initial_access" in tactics
    assert "execution" in tactics


def test_kill_chain_progression_true():
    assert _is_kill_chain_progression({"T1486"}, {"T1566"})  # Impact > Initial Access
    assert _is_kill_chain_progression({"T1059"}, {"T1078"})  # Execution > Initial Access


def test_kill_chain_progression_false():
    assert not _is_kill_chain_progression({"T1566"}, {"T1486"})  # IA < Impact
    assert not _is_kill_chain_progression(set(), {"T1566"})


@patch("nodes.perceive._check_dedup", return_value=False)
def test_gate0_no_duplicate(mock_dedup):
    state: TriageState = {"canonical_alert": _alert()}
    result = gate0_dedup(state)
    assert result.get("correlation_result") is None


@patch("nodes.perceive._check_dedup", return_value=True)
def test_gate0_duplicate(mock_dedup):
    state: TriageState = {"canonical_alert": _alert()}
    result = gate0_dedup(state)
    assert result["correlation_result"].action == "deduplicated"
    assert result["mode"] == "new"


def test_gate0_no_alert():
    state: TriageState = {}
    result = gate0_dedup(state)
    assert result.get("correlation_result") is None


@patch("nodes.perceive.create_react_agent")
def test_perceive_parses_agent_json_new(mock_create_agent):
    fake_agent = MagicMock()
    output = {
        "mitre_mapping": [
            {"tactic": "execution", "technique": "T1059.001", "confidence": "high", "basis": "PowerShell"}
        ],
        "correlation_result": {
            "action": "new",
            "mode": "new",
            "reason": "no_match",
            "confidence": "high",
        },
    }
    fake_agent.invoke.return_value = {"messages": [_FakeMsg("ai", json.dumps(output))]}
    mock_create_agent.return_value = fake_agent

    state: TriageState = {"canonical_alert": _alert()}
    result = perceive(state)

    assert result["mode"] == "new"
    assert result["correlation_result"].action == "new"
    assert len(result["mitre_mapping"]) == 1
    assert result["mitre_mapping"][0].technique == "T1059.001"


@patch("nodes.perceive.create_react_agent")
def test_perceive_parses_agent_json_merge(mock_create_agent):
    fake_agent = MagicMock()
    output = {
        "mitre_mapping": [],
        "correlation_result": {
            "action": "merge",
            "mode": "merge",
            "merge_into_case": "case-42",
            "existing_case_context": {"case_id": "case-42", "title": "Existing"},
            "reason": "entity_match",
            "confidence": "high",
        },
    }
    fake_agent.invoke.return_value = {"messages": [_FakeMsg("ai", json.dumps(output))]}
    mock_create_agent.return_value = fake_agent

    state: TriageState = {"canonical_alert": _alert()}
    result = perceive(state)

    assert result["mode"] == "merge"
    assert result["correlation_result"].merge_into_case == "case-42"
    assert result["existing_case_context"]["case_id"] == "case-42"


@patch("nodes.perceive._find_story_match", return_value=None)
@patch("nodes.perceive._find_merge_candidate", return_value=None)
@patch("nodes.perceive.create_react_agent")
def test_perceive_falls_back_on_unparseable_json(mock_create_agent, mock_merge, mock_story):
    fake_agent = MagicMock()
    fake_agent.invoke.return_value = {"messages": [_FakeMsg("ai", "not json at all")]}
    mock_create_agent.return_value = fake_agent

    state: TriageState = {"canonical_alert": _alert()}
    result = perceive(state)

    assert result["mode"] == "new"
    assert result["correlation_result"].action == "new"
    assert "fallback" in result["correlation_result"].reason
    assert result["mitre_mapping"] == []


@patch("nodes.perceive._find_merge_candidate", return_value={"case_id": "case-9", "title": "t"})
@patch("nodes.perceive.create_react_agent")
def test_perceive_falls_back_to_entity_match_on_agent_exception(mock_create_agent, mock_merge):
    fake_agent = MagicMock()
    fake_agent.invoke.side_effect = RuntimeError("LLM unreachable")
    mock_create_agent.return_value = fake_agent

    state: TriageState = {"canonical_alert": _alert()}
    result = perceive(state)

    assert result["mode"] == "merge"
    assert result["correlation_result"].merge_into_case == "case-9"


def test_perceive_already_deduplicated_short_circuits():
    from schemas import CorrelationResult
    state: TriageState = {
        "canonical_alert": _alert(),
        "correlation_result": CorrelationResult(action="deduplicated", mode="new"),
    }
    result = perceive(state)
    assert result["correlation_result"].action == "deduplicated"


def test_perceive_no_alert():
    state: TriageState = {}
    result = perceive(state)
    assert result.get("correlation_result") is None
