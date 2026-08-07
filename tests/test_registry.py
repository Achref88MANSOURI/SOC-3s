from __future__ import annotations

from unittest.mock import patch

import pytest

from tools.registry import (
    INVESTIGATION_TOOLS,
    PERCEPTION_TOOLS,
    cortex_analyze,
    detection_rule_lookup,
    elasticsearch_query,
    get_case_full,
    get_fp_signal,
    itop_asset_lookup,
    qdrant_retrieve,
    qdrant_retrieve_mitre,
    thehive_fp_history,
    thehive_open_cases,
    thehive_search_closed,
)

# Every test below invokes through `.invoke({...})` rather than calling the
# underlying function directly — that is the path a ReAct agent takes, and the
# one where the generated pydantic schema validates arguments. A direct Python
# call would bypass exactly the validation layer these regressions live in.

ALL_TOOLS = PERCEPTION_TOOLS + INVESTIGATION_TOOLS


def test_no_tool_rejects_explicit_nulls():
    """Regression: Agent 2 called elasticsearch_query with user=None and got
    "user: Input should be a valid string" back instead of a query result.
    An LLM emitting an explicit JSON null for an unused optional argument must
    never fail schema validation, for any tool."""
    for t in ALL_TOOLS:
        args = {name: None for name in t.args_schema.model_fields}
        try:
            t.args_schema(**args)
        except Exception as e:  # pragma: no cover - failure path is the assertion
            pytest.fail(f"{t.name} rejected all-null arguments: {e}")


@patch("tools.registry.query_process_history")
def test_elasticsearch_query_process_with_null_user(mock_process):
    """The exact live failure, end to end through the tool schema."""
    mock_process.return_value = [{"hit": 1}]

    result = elasticsearch_query.invoke({
        "index_type": "process",
        "host": "win-kvkmd51ggkq",
        "user": None,
        "iocs": "",
        "window_hours": 24,
    })

    assert result == [{"hit": 1}]
    mock_process.assert_called_once_with(host="win-kvkmd51ggkq", user=None, window_hours=24)


@patch("tools.registry.query_related_alerts")
def test_elasticsearch_query_defaults_when_everything_null(mock_alerts):
    mock_alerts.return_value = []

    result = elasticsearch_query.invoke({
        "index_type": None, "host": None, "user": None, "iocs": None, "window_hours": None,
    })

    assert result == []
    # index_type falls back to "alerts", window_hours to 24, and no filter is
    # passed as an empty string (which would match nothing rather than be ignored).
    mock_alerts.assert_called_once_with(host=None, user=None, iocs=None, window_hours=24)


@patch("tools.registry.query_connection_history")
def test_elasticsearch_query_connections_splits_iocs(mock_conn):
    mock_conn.return_value = []
    elasticsearch_query.invoke({
        "index_type": "connections", "iocs": "10.0.0.1, 10.0.0.2", "window_hours": None,
    })
    mock_conn.assert_called_once_with(src_ip="10.0.0.1", dst_ip="10.0.0.2", window_hours=24)


@patch("tools.registry.search_open_cases")
def test_thehive_open_cases_null_args_become_none_not_empty_string(mock_search):
    mock_search.return_value = []
    thehive_open_cases.invoke({"observables": None, "host": None, "user": None})
    mock_search.assert_called_once_with(observables=None, host=None, user=None)


@patch("tools.registry.search_closed_cases")
def test_thehive_search_closed_splits_csv_and_nulls(mock_search):
    mock_search.return_value = []
    thehive_search_closed.invoke({"observables": "1.1.1.1, evil.com", "rule_uuid": None})
    mock_search.assert_called_once_with(rule_uuid=None, observables=["1.1.1.1", "evil.com"])


@patch("tools.registry._get_fp_signal")
def test_get_fp_signal_nulls_become_empty_strings(mock_fp):
    mock_fp.return_value = {}
    get_fp_signal.invoke({"rule_uuid": None, "host": None})
    mock_fp.assert_called_once_with("", "")


@patch("tools.registry._thehive_fp_history")
def test_thehive_fp_history_limit_defaults_when_null(mock_hist):
    mock_hist.return_value = []
    thehive_fp_history.invoke({"rule_uuid": "r1", "host": "h1", "limit": None})
    mock_hist.assert_called_once_with("r1", "h1", 3)


@patch("tools.registry.retrieve_mitre")
def test_qdrant_retrieve_mitre_top_k_defaults_and_empty_query_skips_call(mock_retrieve):
    mock_retrieve.return_value = ["hit"]
    assert qdrant_retrieve_mitre.invoke({"query_text": "powershell download", "top_k": None}) == ["hit"]
    mock_retrieve.assert_called_once_with("powershell download", 5)

    mock_retrieve.reset_mock()
    # No query text: return empty rather than sending a meaningless embedding request.
    assert qdrant_retrieve_mitre.invoke({"query_text": None}) == []
    mock_retrieve.assert_not_called()


@patch("tools.registry.retrieve_cve")
def test_qdrant_retrieve_routes_by_collection(mock_cve):
    mock_cve.return_value = ["cve-hit"]
    assert qdrant_retrieve.invoke({"collection": "cve", "query_text": "CVE-2024-1", "top_k": None}) == ["cve-hit"]
    mock_cve.assert_called_once_with("CVE-2024-1", 5)
    # Unknown collection is a no-op, not a crash.
    assert qdrant_retrieve.invoke({"collection": "nope", "query_text": "x"}) == []


def test_required_value_tools_return_error_dict_instead_of_raising():
    """Missing a genuinely required value should come back as a readable error
    the agent can correct from — not an exception that burns the tool call."""
    assert cortex_analyze.invoke({"observable_type": None, "observable_value": None})["error"]
    assert itop_asset_lookup.invoke({"hostname": None})["found"] is False
    assert detection_rule_lookup.invoke({"rule_uuid": None})["found"] is False
    assert get_case_full.invoke({"case_id": None})["found"] is False
