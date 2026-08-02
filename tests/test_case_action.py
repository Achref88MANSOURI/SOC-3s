from __future__ import annotations

from unittest.mock import patch

import pytest

from schemas import MitreMapping, TriageResult
from nodes.case_action import execute_case_action


def _triage_result(**overrides) -> TriageResult:
    defaults = dict(
        alert_id="~alert-1",
        action="create_case",
        verdict="true_positive",
        severity="high",
        reasoning="threat_intel confirmed malicious",
        summary="Confirmed malicious activity on host.",
        mitre_mapping=[MitreMapping(tactic="execution", technique="T1059", confidence="high", basis="evidence")],
    )
    defaults.update(overrides)
    return TriageResult(**defaults)


def test_approved_false_raises_value_error():
    tr = _triage_result()
    with pytest.raises(ValueError):
        execute_case_action(tr, approved=False)


def test_approved_false_raises_before_any_thehive_call():
    tr = _triage_result(action="close_fp")
    with patch("nodes.case_action.update_alert_status") as mock_status:
        with pytest.raises(ValueError):
            execute_case_action(tr, approved=False)
        mock_status.assert_not_called()


@patch("nodes.case_action.add_case_comment")
@patch("nodes.case_action.update_case")
@patch("nodes.case_action.promote_alert_to_case")
def test_create_case_promotes_updates_and_comments(mock_promote, mock_update, mock_comment):
    mock_promote.return_value = {"_id": "case-1"}
    tr = _triage_result(action="create_case")

    result = execute_case_action(tr, approved=True)

    mock_promote.assert_called_once_with("~alert-1")
    args, kwargs = mock_update.call_args
    assert args[0] == "case-1"
    assert kwargs["severity"] == 3  # high -> 3
    assert "execution:T1059" in kwargs["tags"]
    mock_comment.assert_called_once()
    assert result == {"status": "ok", "action": "create_case", "case_id": "case-1"}


@patch("nodes.case_action.promote_alert_to_case")
def test_create_case_promote_failure_returns_error(mock_promote):
    mock_promote.return_value = None
    tr = _triage_result(action="create_case")

    result = execute_case_action(tr, approved=True)

    assert result["status"] == "error"
    assert result["action"] == "create_case"


@patch("nodes.case_action.add_alert_comment")
@patch("nodes.case_action.update_alert_status")
def test_close_fp_updates_status_and_comments(mock_status, mock_comment):
    tr = _triage_result(action="close_fp", verdict="false_positive", reasoning="No TI corroboration")

    result = execute_case_action(tr, approved=True)

    mock_status.assert_called_once_with("~alert-1", "FP")
    mock_comment.assert_called_once_with("~alert-1", "No TI corroboration")
    assert result == {"status": "ok", "action": "close_fp", "alert_id": "~alert-1"}


@patch("nodes.case_action.add_case_comment")
@patch("nodes.case_action.merge_alert_into_case")
def test_merge_quiet_merges_and_comments(mock_merge, mock_comment):
    tr = _triage_result(action="merge_quiet", merge_into_case="case-42")

    result = execute_case_action(tr, approved=True)

    mock_merge.assert_called_once_with("~alert-1", "case-42")
    mock_comment.assert_called_once()
    assert result == {"status": "ok", "action": "merge_quiet", "case_id": "case-42"}


def test_merge_quiet_without_case_id_returns_error():
    tr = _triage_result(action="merge_quiet", merge_into_case=None)

    result = execute_case_action(tr, approved=True)

    assert result["status"] == "error"
    assert result["action"] == "merge_quiet"


@patch("nodes.case_action.add_case_comment")
@patch("nodes.case_action.update_case")
@patch("nodes.case_action.merge_alert_into_case")
def test_merge_and_retier_merges_updates_severity_and_flags_notification(mock_merge, mock_update, mock_comment):
    tr = _triage_result(action="merge_and_retier", merge_into_case="case-42", severity="critical")

    result = execute_case_action(tr, approved=True)

    mock_merge.assert_called_once_with("~alert-1", "case-42")
    mock_update.assert_called_once_with("case-42", severity=4)  # critical -> 4
    mock_comment.assert_called_once()
    assert result["status"] == "ok"
    assert result["urgent_notification_required"] is True


def test_merge_and_retier_without_case_id_returns_error():
    tr = _triage_result(action="merge_and_retier", merge_into_case=None)

    result = execute_case_action(tr, approved=True)

    assert result["status"] == "error"
    assert result["action"] == "merge_and_retier"


def test_unknown_action_handled_gracefully():
    tr = _triage_result(action="needs_review")

    result = execute_case_action(tr, approved=True)

    assert result == {
        "status": "skipped",
        "action": "needs_review",
        "reason": "No case action defined for action 'needs_review'",
    }


def test_deduplicated_action_handled_gracefully():
    tr = _triage_result(action="deduplicated")

    result = execute_case_action(tr, approved=True)

    assert result["status"] == "skipped"
