from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import shlex

from langchain_mcp_adapters.client import MultiServerMCPClient

from config import CORTEX_API_KEY, CORTEX_MCP_ARGS, CORTEX_MCP_COMMAND, CORTEX_MCP_CORTEX_URL

logger = logging.getLogger("agent-service.cortex_mcp")

_SERVER_NAME = "cortex"

# Tool schema confirmed by source review of solomonneas/cortex-mcp (analyzers.ts,
# jobs.ts). Only the three tools Agent 2 actually needs are wired up here — see
# CHANGES.md for the tools deliberately skipped (cortex_run_analyzer,
# cortex_get_job, cortex_get_job_report, cortex_run_analyzer_file).
_tools_cache: dict[str, object] | None = None


def _connection() -> dict:
    return {
        _SERVER_NAME: {
            "transport": "stdio",
            "command": CORTEX_MCP_COMMAND,
            "args": shlex.split(CORTEX_MCP_ARGS) if CORTEX_MCP_ARGS else [],
            "env": {
                "CORTEX_URL": CORTEX_MCP_CORTEX_URL,
                "CORTEX_API_KEY": CORTEX_API_KEY,
            },
        }
    }


async def _get_tool_async(tool_name: str):
    global _tools_cache
    if _tools_cache is None:
        client = MultiServerMCPClient(_connection())
        tools = await client.get_tools()
        _tools_cache = {t.name: t for t in tools}
    tool = _tools_cache.get(tool_name)
    if tool is None:
        raise RuntimeError(
            f"cortex-mcp did not expose tool '{tool_name}'. Available: {sorted(_tools_cache)}"
        )
    return tool


async def _call_async(tool_name: str, **kwargs) -> object:
    tool = await _get_tool_async(tool_name)
    return await tool.ainvoke(kwargs)


def _run_async(tool_name: str, **kwargs) -> object:
    """MCP's client is async-only, and get_tools()/ainvoke() each spawn their own
    stdio session. main.py's /triage handler is an async FastAPI route, so this can
    be called from inside an already-running event loop — asyncio.run() would raise
    'cannot be called from a running event loop' in that case. Run in a fresh thread
    (with its own fresh loop) whenever one is already active; use asyncio.run()
    directly otherwise (e.g. plain scripts, pytest)."""
    coro = _call_async(tool_name, **kwargs)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _coerce_dict(result: object) -> dict:
    if isinstance(result, dict):
        return result
    if isinstance(result, str):
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"raw": result}
    if isinstance(result, list):
        # MCP text content blocks: [{"type": "text", "text": "..."}]
        texts = [b.get("text", "") for b in result if isinstance(b, dict) and b.get("type") == "text"]
        if texts:
            joined = "\n".join(texts)
            try:
                return json.loads(joined)
            except json.JSONDecodeError:
                return {"raw": joined}
        return {"raw": str(result)}
    return {"raw": str(result)}


def _call(tool_name: str, **kwargs) -> dict:
    if not CORTEX_MCP_COMMAND:
        return {"error": "cortex-mcp not configured (CORTEX_MCP_COMMAND unset)"}
    try:
        result = _run_async(tool_name, **kwargs)
    except Exception as e:
        logger.error("cortex-mcp call to '%s' failed: %s", tool_name, str(e))
        return {"error": str(e)}
    return _coerce_dict(result)


def list_analyzers(data_type: str | None = None) -> dict:
    """List Cortex analyzers available via cortex-mcp, optionally filtered by
    observable dataType (ip|domain|url|fqdn|hash|mail|filename|registry|regexp|other)."""
    kwargs = {"dataType": data_type} if data_type else {}
    return _call("cortex_list_analyzers", **kwargs)


def run_analyzer_by_name(analyzer_name: str, data_type: str, data: str, tlp: int = 2, pap: int = 2) -> dict:
    """Submit a Cortex analyzer job via cortex-mcp by analyzer name. Returns
    {jobId, analyzerUsed} — pass jobId to wait_and_get_report next."""
    return _call(
        "cortex_run_analyzer_by_name",
        analyzerName=analyzer_name,
        dataType=data_type,
        data=data,
        tlp=tlp,
        pap=pap,
    )


def wait_and_get_report(job_id: str, timeout: int | None = None) -> dict:
    """Wait for a submitted Cortex job (from run_analyzer_by_name's jobId) to finish
    and return its full report with verdict taxonomies, in one call."""
    kwargs: dict = {"jobId": job_id}
    if timeout is not None:
        kwargs["timeout"] = timeout
    return _call("cortex_wait_and_get_report", **kwargs)
