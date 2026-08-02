from __future__ import annotations

from unittest.mock import patch

from tools.thehive import get_full_alert_with_analysis


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
