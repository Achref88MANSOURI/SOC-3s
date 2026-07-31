from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

from schemas import CanonicalAlert, Rule, TriageState
from nodes.correlate import (
    _is_kill_chain_progression,
    _tactic_index,
    _tactics_from_techniques,
    correlate,
)


def _alert(rule_uuid: str = "uuid-abc", hostname: str | None = "srv-01") -> CanonicalAlert:
    return CanonicalAlert(
        alert_id="test-001",
        timestamp=datetime.now(timezone.utc),
        source_engine="suricata",
        investigation_profile="network_threat",
        rule=Rule(name="test-rule", uuid=rule_uuid, native_severity=2),
        host=__import__("schemas").Host(hostname=hostname) if hostname else None,
    )


def test_tactic_index():
    assert _tactic_index("initial_access") == 2
    assert _tactic_index("execution") == 3
    assert _tactic_index("exfiltration") == 12
    assert _tactic_index("impact") == 13
    assert _tactic_index("unknown_tactic") == -1


def test_tactics_from_techniques():
    tactics = _tactics_from_techniques({"T1566", "T1059"})
    assert "initial_access" in tactics
    assert "execution" in tactics
    assert len(tactics) == 2


def test_tactics_from_empty():
    assert _tactics_from_techniques(set()) == set()
    assert _tactics_from_techniques({"T9999"}) == set()


def test_kill_chain_progression_true():
    """Alert introduces a later-stage tactic than the case."""
    assert _is_kill_chain_progression({"T1486"}, {"T1566"})  # Impact > Initial Access
    assert _is_kill_chain_progression({"T1059"}, {"T1078"})  # Execution > Initial Access
    assert _is_kill_chain_progression({"T1048"}, {"T1059"})  # Exfiltration > Execution


def test_kill_chain_progression_false():
    """Alert is same or earlier stage."""
    assert not _is_kill_chain_progression({"T1566"}, {"T1486"})  # Initial Access < Impact
    assert not _is_kill_chain_progression({"T1059"}, {"T1486"})  # Execution < Impact
    assert not _is_kill_chain_progression({"T1566"}, {"T1071"})  # IA < C2, no progression


def test_kill_chain_no_match():
    assert not _is_kill_chain_progression(set(), {"T1566"})
    assert not _is_kill_chain_progression({"T1566"}, set())
    assert not _is_kill_chain_progression(set(), set())


def test_kill_chain_unknown_techniques():
    assert not _is_kill_chain_progression({"T9999"}, {"T1566"})


def test_kill_chain_full_range():
    """Test across the full tactic order."""
    for later in ("execution", "persistence", "lateral_movement", "exfiltration", "impact"):
        later_tech = [t for t, tacs in [
            ("T1059", "execution"), ("T1547", "persistence"),
            ("T1021", "lateral_movement"), ("T1048", "exfiltration"), ("T1486", "impact"),
        ] if tacs == later]
        earlier_tech = [t for t, tacs in [
            ("T1566", "initial_access"), ("T1078", "initial_access"),
        ] if tacs == later]
        if later_tech:
            assert _is_kill_chain_progression(set(later_tech[:1]), {"T1566"}), f"{later} > IA"


@patch("nodes.correlate._check_dedup", return_value={"is_duplicate": False})
@patch("nodes.correlate._find_merge_candidate", return_value=None)
@patch("nodes.correlate._find_story_match", return_value=None)
def test_correlate_new(mock_story, mock_merge, mock_dedup):
    state: TriageState = {"canonical_alert": _alert()}
    result = correlate(state)
    assert result["mode"] == "new"
    assert result["correlation_result"].action == "new"


@patch("nodes.correlate._check_dedup", return_value={"is_duplicate": True})
def test_correlate_dedup(mock_dedup):
    state: TriageState = {"canonical_alert": _alert()}
    result = correlate(state)
    assert result["mode"] == "new"
    assert result["correlation_result"].action == "deduplicated"


@patch("nodes.correlate._check_dedup", return_value={"is_duplicate": False})
@patch("nodes.correlate._find_merge_candidate")
def test_correlate_entity_match(mock_merge, mock_dedup):
    mock_merge.return_value = {"case_id": "case-001", "title": "Existing case"}
    state: TriageState = {"canonical_alert": _alert()}
    result = correlate(state)
    assert result["mode"] == "merge"
    assert result["correlation_result"].action == "merge"
    assert result["correlation_result"].merge_into_case == "case-001"
    assert "Entity match" in result["correlation_result"].reason


@patch("nodes.correlate._check_dedup", return_value={"is_duplicate": False})
@patch("nodes.correlate._find_merge_candidate", return_value=None)
@patch("nodes.correlate._find_story_match")
def test_correlate_story_match(mock_story, mock_merge, mock_dedup):
    mock_story.return_value = {"case_id": "case-005", "title": "Kill chain case"}
    state: TriageState = {"canonical_alert": _alert()}
    result = correlate(state)
    assert result["mode"] == "merge"
    assert result["correlation_result"].action == "merge"
    assert result["correlation_result"].merge_into_case == "case-005"
    assert "Kill-chain" in result["correlation_result"].reason


@patch("nodes.correlate._check_dedup", return_value={"is_duplicate": False})
@patch("nodes.correlate._find_merge_candidate", return_value=None)
@patch("nodes.correlate._find_story_match", return_value=None)
def test_correlate_no_host(mock_story, mock_merge, mock_dedup):
    alert = _alert(hostname=None)
    state: TriageState = {"canonical_alert": alert}
    result = correlate(state)
    assert result["mode"] == "new"
    assert result["correlation_result"].action == "new"
