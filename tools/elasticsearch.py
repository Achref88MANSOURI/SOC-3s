from __future__ import annotations

from datetime import datetime, timedelta, timezone

import requests

from config import ES_API_KEY, ES_URL

REQUEST_TIMEOUT = 30
DEFAULT_WINDOW_HOURS = 24
MAX_RESULTS = 50


def _headers():
    headers = {"Content-Type": "application/json"}
    if ES_API_KEY:
        headers["Authorization"] = f"ApiKey {ES_API_KEY}"
    return headers


def _es_post(path: str, body: dict) -> dict:
    resp = requests.post(
        f"{ES_URL}{path}",
        headers=_headers(),
        json=body,
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def _summarize_hits(hits: list[dict]) -> list[dict]:
    summaries = []
    for hit in hits:
        src = hit.get("_source", {})
        summaries.append({
            "timestamp": src.get("@timestamp", ""),
            "rule_name": src.get("rule", {}).get("name", ""),
            "rule_uuid": src.get("rule", {}).get("uuid", ""),
            "severity": src.get("severity", src.get("rule", {}).get("severity", "")),
            "src_ip": src.get("src_ip", ""),
            "dst_ip": src.get("dst_ip", ""),
            "hostname": src.get("host", {}).get("hostname", src.get("hostname", "")),
            "username": src.get("user", {}).get("name", src.get("username", "")),
            "category": src.get("rule", {}).get("category", ""),
        })
    return summaries


def query_related_alerts(
    host: str | None = None,
    user: str | None = None,
    iocs: list[str] | None = None,
    window_hours: int = DEFAULT_WINDOW_HOURS,
) -> list[dict]:
    filters = []
    since = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()

    filters.append({"range": {"@timestamp": {"gte": since}}})

    if host:
        filters.append({"multi_match": {"query": host, "fields": ["host.hostname", "hostname", "src_ip", "dst_ip"]}})
    if user:
        filters.append({"multi_match": {"query": user, "fields": ["user.name", "username"]}})
    if iocs:
        for ioc in iocs:
            filters.append({"multi_match": {"query": ioc, "fields": ["src_ip", "dst_ip", "domain", "url", "file.hash.md5", "file.hash.sha1", "file.hash.sha256"]}})

    if not filters:
        return []

    body = {
        "size": MAX_RESULTS,
        "query": {"bool": {"filter": filters}},
        "sort": [{"@timestamp": "desc"}],
    }

    try:
        result = _es_post("/.ds-logs-detections.alerts-so-*/_search", body)
        hits = result.get("hits", {}).get("hits", [])
        return _summarize_hits(hits)
    except requests.exceptions.RequestException:
        return []


def query_process_history(
    host: str | None = None,
    user: str | None = None,
    window_hours: int = DEFAULT_WINDOW_HOURS,
) -> list[dict]:
    if not host and not user:
        return []

    filters = []
    since = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
    filters.append({"range": {"@timestamp": {"gte": since}}})

    if host:
        filters.append({"multi_match": {"query": host, "fields": ["host.hostname", "hostname"]}})
    if user:
        filters.append({"multi_match": {"query": user, "fields": ["user.name", "username"]}})

    body = {
        "size": MAX_RESULTS,
        "query": {"bool": {"filter": filters}},
        "_source": ["@timestamp", "process.name", "process.path", "process.command_line", "process.pid", "host.hostname", "user.name"],
        "sort": [{"@timestamp": "desc"}],
    }

    try:
        result = _es_post("/.ds-logs-endpoint.process-*/_search", body)
        hits = result.get("hits", {}).get("hits", [])
        return [
            {
                "timestamp": h.get("_source", {}).get("@timestamp", ""),
                "hostname": h.get("_source", {}).get("host", {}).get("hostname", ""),
                "user": h.get("_source", {}).get("user", {}).get("name", ""),
                "process_name": h.get("_source", {}).get("process", {}).get("name", ""),
                "process_path": h.get("_source", {}).get("process", {}).get("path", ""),
                "command_line": h.get("_source", {}).get("process", {}).get("command_line", ""),
                "pid": h.get("_source", {}).get("process", {}).get("pid"),
            }
            for h in hits
        ]
    except requests.exceptions.RequestException:
        return []


def query_connection_history(
    src_ip: str | None = None,
    dst_ip: str | None = None,
    window_hours: int = DEFAULT_WINDOW_HOURS,
) -> list[dict]:
    filters = []
    since = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
    filters.append({"range": {"@timestamp": {"gte": since}}})

    if src_ip:
        filters.append({"term": {"src_ip": src_ip}})
    if dst_ip:
        filters.append({"term": {"dst_ip": dst_ip}})

    if not filters:
        return []

    body = {
        "size": MAX_RESULTS,
        "query": {"bool": {"filter": filters}},
        "_source": ["@timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "network.bytes", "event.action", "host.hostname"],
        "sort": [{"@timestamp": "desc"}],
    }

    try:
        result = _es_post("/.ds-logs-network.flow-*/_search", body)
        hits = result.get("hits", {}).get("hits", [])
        return [
            {
                "timestamp": h.get("_source", {}).get("@timestamp", ""),
                "src_ip": h.get("_source", {}).get("src_ip", ""),
                "dst_ip": h.get("_source", {}).get("dst_ip", ""),
                "src_port": h.get("_source", {}).get("src_port"),
                "dst_port": h.get("_source", {}).get("dst_port"),
                "protocol": h.get("_source", {}).get("protocol", ""),
                "bytes": h.get("_source", {}).get("network", {}).get("bytes"),
                "action": h.get("_source", {}).get("event", {}).get("action", ""),
                "hostname": h.get("_source", {}).get("host", {}).get("hostname", ""),
            }
            for h in hits
        ]
    except requests.exceptions.RequestException:
        return []
