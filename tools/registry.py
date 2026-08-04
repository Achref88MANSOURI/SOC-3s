from __future__ import annotations

from langchain_core.tools import tool

from tools.cortex import analyze_observable as _cortex_analyze
from tools.elasticsearch import query_related_alerts, query_process_history, query_connection_history
from tools.itop import lookup_asset as _itop_lookup
from tools.qdrant import retrieve_mitre, retrieve_playbooks, retrieve_cve
from tools.detection_rules import get_rule_source as _detection_rule
from tools.thehive import search_open_cases, search_closed_cases, get_case_full


@tool
def cortex_analyze(observable_type: str, observable_value: str) -> dict:
    """Run threat intelligence on an observable (ip, domain, url, hash). Returns verdict with score."""
    return _cortex_analyze(observable_type, observable_value)


@tool
def itop_asset_lookup(hostname: str) -> dict:
    """Look up asset context from iTop CMDB by hostname or IP address.
    Pass the hostname or IP as 'hostname' parameter.
    Returns criticality, owner, department, services, network_zone."""
    return _itop_lookup(hostname)


@tool
def elasticsearch_query(index_type: str = "alerts", host: str = "", user: str = "", iocs: str = "", window_hours: int = 24) -> list:
    """Query Elasticsearch for recent security events.
    index_type: 'alerts' (default), 'process', or 'connections'.
    host: filter by hostname or IP.
    user: filter by username.
    iocs: comma-separated IOCs for alert search.
    window_hours: lookback window (default 24).
    """
    ioc_list = [s.strip() for s in iocs.split(",") if s.strip()] if iocs else []
    if index_type == "alerts":
        return query_related_alerts(host=host or None, user=user or None, iocs=ioc_list or None, window_hours=window_hours)
    elif index_type == "process":
        return query_process_history(host=host or None, user=user or None, window_hours=window_hours)
    elif index_type == "connections":
        parts = ioc_list
        src = parts[0] if len(parts) > 0 else host
        dst = parts[1] if len(parts) > 1 else None
        return query_connection_history(src_ip=src or None, dst_ip=dst, window_hours=window_hours)
    return []


@tool
def thehive_search(query_type: str, observables: str = "", host: str = "", user: str = "", case_id: str = "") -> list | dict:
    """Search TheHive for cases.
    query_type: 'open_cases' (find by observable/host/user), 'closed_cases', or 'get_case'.
    """
    obs_list = [s.strip() for s in observables.split(",") if s.strip()] if observables else []

    if query_type == "open_cases":
        return search_open_cases(observables=obs_list or None, host=host or None, user=user or None)
    elif query_type == "closed_cases":
        return search_closed_cases(observables=obs_list or None)
    elif query_type == "get_case" and case_id:
        result = get_case_full(case_id)
        return result or {"error": "Case not found", "case_id": case_id}
    return []


@tool
def sigma_rule_lookup(rule_uuid: str) -> dict:
    """Look up a Sigma rule by UUID from the local filesystem. Returns description, FP conditions, MITRE tags."""
    return _detection_rule(rule_uuid)


@tool
def qdrant_retrieve(collection: str, query_text: str, top_k: int = 5) -> list:
    """Search Qdrant vector DB for MITRE techniques, playbooks, or CVEs.
    collection: 'mitre_attack', 'playbooks', or 'cve'.
    Returns relevant matches with scores.
    """
    if collection == "mitre_attack":
        return retrieve_mitre(query_text, top_k)
    elif collection == "playbooks":
        return retrieve_playbooks(query_text, top_k)
    elif collection == "cve":
        return retrieve_cve(query_text, top_k)
    return []


@tool
def qdrant_retrieve_mitre(query_text: str, top_k: int = 5) -> list:
    """Search Qdrant for candidate MITRE ATT&CK techniques matching a description
    of the alert's behavior (rule name, description, command line, etc). Use this
    when no explicit attack.txxxx tags are available from sigma_rule_lookup."""
    return retrieve_mitre(query_text, top_k)


@tool
def thehive_open_cases(observables: str = "", host: str = "", user: str = "") -> list:
    """Search TheHive for open/in-progress cases sharing an observable, host, or
    user with this alert. observables is a comma-separated list of IPs/domains/hashes."""
    obs_list = [s.strip() for s in observables.split(",") if s.strip()] if observables else []
    return search_open_cases(observables=obs_list or None, host=host or None, user=user or None)


TOOLS = [
    cortex_analyze,
    itop_asset_lookup,
    elasticsearch_query,
    thehive_search,
    sigma_rule_lookup,
    qdrant_retrieve,
]

PERCEPTION_TOOLS = [
    sigma_rule_lookup,
    qdrant_retrieve_mitre,
    thehive_open_cases,
]
