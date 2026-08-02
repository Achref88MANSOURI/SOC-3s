from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import tools.cortex_mcp as cortex_mcp


def _fake_tool(name, result):
    t = MagicMock()
    t.name = name
    t.ainvoke = AsyncMock(return_value=result)
    return t


def setup_function(_):
    cortex_mcp._tools_cache = None


def test_connection_builds_stdio_config_with_split_args():
    with patch("tools.cortex_mcp.CORTEX_MCP_COMMAND", "node"), \
         patch("tools.cortex_mcp.CORTEX_MCP_ARGS", "/opt/cortex-mcp/dist/index.js"), \
         patch("tools.cortex_mcp.CORTEX_MCP_CORTEX_URL", "http://172.20.24.221:9001"), \
         patch("tools.cortex_mcp.CORTEX_API_KEY", "secret-key"):
        conn = cortex_mcp._connection()

    cortex_conn = conn["cortex"]
    assert cortex_conn["transport"] == "stdio"
    assert cortex_conn["command"] == "node"
    assert cortex_conn["args"] == ["/opt/cortex-mcp/dist/index.js"]
    assert cortex_conn["env"]["CORTEX_URL"] == "http://172.20.24.221:9001"
    assert cortex_conn["env"]["CORTEX_API_KEY"] == "secret-key"


def test_call_returns_error_when_not_configured():
    with patch("tools.cortex_mcp.CORTEX_MCP_COMMAND", ""):
        result = cortex_mcp._call("cortex_list_analyzers")
    assert "error" in result
    assert "not configured" in result["error"]


@patch("tools.cortex_mcp.CORTEX_MCP_COMMAND", "node")
@patch("tools.cortex_mcp.MultiServerMCPClient")
def test_list_analyzers_calls_correct_tool_and_args(mock_client_cls):
    fake_client = MagicMock()
    fake_client.get_tools = AsyncMock(return_value=[
        _fake_tool("cortex_list_analyzers", {"analyzers": ["VirusTotal", "AbuseIPDB"]}),
    ])
    mock_client_cls.return_value = fake_client

    result = cortex_mcp.list_analyzers("hash")

    assert result == {"analyzers": ["VirusTotal", "AbuseIPDB"]}


@patch("tools.cortex_mcp.CORTEX_MCP_COMMAND", "node")
@patch("tools.cortex_mcp.MultiServerMCPClient")
def test_list_analyzers_omits_data_type_when_none(mock_client_cls):
    tool = _fake_tool("cortex_list_analyzers", {"analyzers": []})
    fake_client = MagicMock()
    fake_client.get_tools = AsyncMock(return_value=[tool])
    mock_client_cls.return_value = fake_client

    cortex_mcp.list_analyzers()

    tool.ainvoke.assert_awaited_once_with({})


@patch("tools.cortex_mcp.CORTEX_MCP_COMMAND", "node")
@patch("tools.cortex_mcp.MultiServerMCPClient")
def test_run_analyzer_by_name_passes_all_args(mock_client_cls):
    tool = _fake_tool("cortex_run_analyzer_by_name", {"jobId": "job-1", "analyzerUsed": "VirusTotal"})
    fake_client = MagicMock()
    fake_client.get_tools = AsyncMock(return_value=[tool])
    mock_client_cls.return_value = fake_client

    result = cortex_mcp.run_analyzer_by_name("VirusTotal", "hash", "1c84c863", tlp=1, pap=1)

    assert result == {"jobId": "job-1", "analyzerUsed": "VirusTotal"}
    tool.ainvoke.assert_awaited_once_with({
        "analyzerName": "VirusTotal",
        "dataType": "hash",
        "data": "1c84c863",
        "tlp": 1,
        "pap": 1,
    })


@patch("tools.cortex_mcp.CORTEX_MCP_COMMAND", "node")
@patch("tools.cortex_mcp.MultiServerMCPClient")
def test_wait_and_get_report_with_and_without_timeout(mock_client_cls):
    tool = _fake_tool("cortex_wait_and_get_report", {"status": "Success"})
    fake_client = MagicMock()
    fake_client.get_tools = AsyncMock(return_value=[tool])
    mock_client_cls.return_value = fake_client

    cortex_mcp.wait_and_get_report("job-1")
    tool.ainvoke.assert_awaited_with({"jobId": "job-1"})

    cortex_mcp.wait_and_get_report("job-1", timeout=60)
    tool.ainvoke.assert_awaited_with({"jobId": "job-1", "timeout": 60})


@patch("tools.cortex_mcp.CORTEX_MCP_COMMAND", "node")
@patch("tools.cortex_mcp.MultiServerMCPClient")
def test_tools_are_cached_across_calls(mock_client_cls):
    tool = _fake_tool("cortex_list_analyzers", {"analyzers": []})
    fake_client = MagicMock()
    fake_client.get_tools = AsyncMock(return_value=[tool])
    mock_client_cls.return_value = fake_client

    cortex_mcp.list_analyzers()
    cortex_mcp.list_analyzers()

    fake_client.get_tools.assert_awaited_once()
    assert tool.ainvoke.await_count == 2


@patch("tools.cortex_mcp.CORTEX_MCP_COMMAND", "node")
@patch("tools.cortex_mcp.MultiServerMCPClient")
def test_unknown_tool_name_returns_error(mock_client_cls):
    fake_client = MagicMock()
    fake_client.get_tools = AsyncMock(return_value=[_fake_tool("some_other_tool", {})])
    mock_client_cls.return_value = fake_client

    result = cortex_mcp.list_analyzers()

    assert "error" in result
    assert "cortex_list_analyzers" in result["error"]


@patch("tools.cortex_mcp.CORTEX_MCP_COMMAND", "node")
@patch("tools.cortex_mcp.MultiServerMCPClient")
def test_tool_exception_is_caught_and_returned_as_error(mock_client_cls):
    tool = _fake_tool("cortex_list_analyzers", {})
    tool.ainvoke = AsyncMock(side_effect=RuntimeError("stdio process crashed"))
    fake_client = MagicMock()
    fake_client.get_tools = AsyncMock(return_value=[tool])
    mock_client_cls.return_value = fake_client

    result = cortex_mcp.list_analyzers()

    assert "error" in result
    assert "stdio process crashed" in result["error"]


def test_coerce_dict_handles_dict():
    assert cortex_mcp._coerce_dict({"a": 1}) == {"a": 1}


def test_coerce_dict_handles_json_string():
    assert cortex_mcp._coerce_dict('{"a": 1}') == {"a": 1}


def test_coerce_dict_handles_non_json_string():
    assert cortex_mcp._coerce_dict("plain text") == {"raw": "plain text"}


def test_coerce_dict_handles_text_content_blocks():
    blocks = [{"type": "text", "text": '{"jobId": "job-9"}'}]
    assert cortex_mcp._coerce_dict(blocks) == {"jobId": "job-9"}


def test_coerce_dict_handles_non_json_text_blocks():
    blocks = [{"type": "text", "text": "not json"}]
    assert cortex_mcp._coerce_dict(blocks) == {"raw": "not json"}
