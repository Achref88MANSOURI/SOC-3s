from __future__ import annotations

from unittest.mock import patch

from tools.thehive import get_case_full, get_full_alert_with_analysis, search_fp_history


def _alert_response():
    return [{"_id": "~15401056", "title": "Execution Of Non-Existing File", "severity": 3}]


def _observables_response():
    return [
        {
            "_id": "~506892376",
            "dataType": "hash",
            "data": "a56d8db4",
            "reports": {"VirusTotal_GetReport_3_0": {"summary": {"taxonomies": []}}},
        },
        {"_id": "~56582208", "dataType": "fqdn", "data": "soc-vostro-3910", "reports": {}},
    ]


@patch("tools.thehive._thehive_post")
def test_get_full_alert_with_analysis_merges_observables(mock_post):
    mock_post.side_effect = [_alert_response(), _observables_response()]

    result = get_full_alert_with_analysis("~15401056")

    assert result["_id"] == "~15401056"
    assert result["title"] == "Execution Of Non-Existing File"
    assert len(result["observables"]) == 2
    assert result["observables"][0]["reports"]["VirusTotal_GetReport_3_0"]

    # Confirms the extraData=["reports"] mechanism was requested on the observables call.
    second_call_body = mock_post.call_args_list[1].args[1]
    assert second_call_body["extraData"] == ["reports"]
    assert second_call_body["query"][0]["_name"] == "getAlert"
    assert second_call_body["query"][1]["_name"] == "observables"


@patch("tools.thehive._thehive_post")
def test_get_full_alert_with_analysis_alert_not_found(mock_post):
    mock_post.return_value = []
    result = get_full_alert_with_analysis("~doesnotexist")
    assert result is None


@patch("tools.thehive._thehive_post")
def test_get_full_alert_with_analysis_observables_fetch_fails(mock_post):
    import requests

    mock_post.side_effect = [_alert_response(), requests.exceptions.RequestException("timeout")]

    result = get_full_alert_with_analysis("~15401056")

    assert result["_id"] == "~15401056"
    assert result["observables"] == []


@patch("tools.thehive._thehive_post")
def test_get_full_alert_with_analysis_alert_fetch_fails(mock_post):
    import requests

    mock_post.side_effect = requests.exceptions.RequestException("connection refused")
    result = get_full_alert_with_analysis("~15401056")
    assert result is None


@patch("tools.thehive._thehive_post")
def test_search_fp_history_returns_ignored_alerts(mock_post):
    mock_post.return_value = [
        {"_id": "~1", "title": "Suspicious PowerShell", "summary": "Confirmed FP: admin script", "updatedAt": "2026-07-01"},
    ]

    result = search_fp_history("rule-uuid-1", "srv-01", limit=3)

    assert len(result) == 1
    assert result[0]["alert_id"] == "~1"
    assert result[0]["comment"] == "Confirmed FP: admin script"
    body = mock_post.call_args.args[1]
    assert body["filter"] == [{"terms": {"status": ["Ignored"]}}]
    assert body["size"] == 3


def test_search_fp_history_missing_rule_or_host_returns_empty_without_query():
    with patch("tools.thehive._thehive_post") as mock_post:
        assert search_fp_history("", "srv-01") == []
        assert search_fp_history("rule-1", "") == []
        mock_post.assert_not_called()


@patch("tools.thehive._thehive_post")
def test_search_fp_history_request_failure_returns_empty(mock_post):
    import requests

    mock_post.side_effect = requests.exceptions.RequestException("timeout")
    assert search_fp_history("rule-1", "srv-01") == []


@patch("tools.thehive._thehive_get")
def test_get_case_full_returns_case_details(mock_get):
    mock_get.return_value = {
        "_id": "~case-1",
        "title": "Ransomware on srv-01",
        "description": "d",
        "severity": 3,
        "status": "Open",
        "tags": ["ransomware"],
        "metrics": {},
        "customFields": {},
        "createdAt": "2026-07-01",
        "owner": "analyst1",
        "summary": "s",
    }

    result = get_case_full("~case-1")

    assert result["case_id"] == "~case-1"
    assert result["title"] == "Ransomware on srv-01"
    assert result["severity"] == 3


@patch("tools.thehive._thehive_get")
def test_get_case_full_request_failure_returns_none(mock_get):
    import requests

    mock_get.side_effect = requests.exceptions.RequestException("not found")
    assert get_case_full("~doesnotexist") is None
