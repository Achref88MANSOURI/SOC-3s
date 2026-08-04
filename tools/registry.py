from __future__ import annotations

from langchain_core.tools import tool

from tools.cortex import analyze_observable as _cortex_analyze
from tools.detection_rules import get_rule_source as _detection_rule
from tools.elasticsearch import query_related_alerts, query_process_history, query_connection_history
from tools.fp_tracking import get_fp_signal as _get_fp_signal, thehive_fp_history as _thehive_fp_history
from tools.itop import lookup_asset as _itop_lookup
from tools.qdrant import retrieve_mitre, retrieve_playbooks, retrieve_cve
from tools.thehive import search_open_cases, search_closed_cases, get_case_full as _get_case_full


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
def thehive_search_closed(observables: str = "", rule_uuid: str = "") -> list:
    """Search TheHive for resolved/closed cases — "has this rule fired before,
    what happened?" observables is a comma-separated list of IPs/domains/hashes.
    Agent 2 only — open-case correlation is Agent 1's job (thehive_open_cases)."""
    obs_list = [s.strip() for s in observables.split(",") if s.strip()] if observables else []
    return search_closed_cases(rule_uuid=rule_uuid or None, observables=obs_list or None)


@tool
def detection_rule_lookup(rule_uuid: str, source_engine: str = "") -> dict:
    """Look up a detection rule's source and MITRE ATT&CK metadata by UUID,
    across all three Security Onion engines. Pass source_engine ('sigma',
    'suricata', or 'yara'/'strelka') if known — the alert's source_engine field
    tells you this — to skip straight to the right lookup. If omitted, tries
    Sigma YAML, then Suricata .rules metadata, then falls back to YARA's
    graceful "no lookup mechanism exists" response. Suricata and Sigma results
    include a `mitre_attack` list of technique IDs when the rule has them —
    absence is common and not an error (only ~50% of Suricata rules carry
    MITRE metadata). YARA never returns a real lookup — it has no
    centrally indexed rule source or native MITRE tagging convention."""
    return _detection_rule(rule_uuid, source_engine or None)


@tool
def qdrant_retrieve(collection: str, query_text: str, top_k: int = 5) -> list:
    """Search Qdrant vector DB for playbooks or CVEs. collection: 'playbooks' or
    'cve'. Returns relevant matches with scores. For MITRE technique search,
    that's Agent 1's tool (qdrant_retrieve_mitre) — not available here."""
    if collection == "playbooks":
        return retrieve_playbooks(query_text, top_k)
    elif collection == "cve":
        return retrieve_cve(query_text, top_k)
    return []


@tool
def qdrant_retrieve_mitre(query_text: str, top_k: int = 5) -> list:
    """Search Qdrant for candidate MITRE ATT&CK techniques matching a description
    of the alert's behavior (rule name, description, command line, etc). Use this
    when no explicit MITRE tags are available from detection_rule_lookup."""
    return retrieve_mitre(query_text, top_k)


@tool
def thehive_open_cases(observables: str = "", host: str = "", user: str = "") -> list:
    """Search TheHive for open/in-progress cases sharing an observable, host, or
    user with this alert. observables is a comma-separated list of IPs/domains/hashes."""
    obs_list = [s.strip() for s in observables.split(",") if s.strip()] if observables else []
    return search_open_cases(observables=obs_list or None, host=host or None, user=user or None)


@tool
def get_case_full(case_id: str) -> dict:
    """Fetch full content (description, severity, tags, metrics, custom fields,
    summary) of a specific TheHive case by ID. Call this AFTER thehive_open_cases
    finds a candidate case, to read its actual content before deciding merge vs
    new — thehive_open_cases only returns a shallow list, not enough to reason
    about match strength or kill-chain progression on its own."""
    result = _get_case_full(case_id)
    return result or {"found": False, "case_id": case_id}


@tool
def get_fp_signal(rule_uuid: str, host: str) -> dict:
    """Check this rule/host combo's historical false-positive rate before
    investigating further — instant, local, always call this FIRST. Returns
    short_term (24h) and long_term (30d) fp_rate + total sample count for
    each window. A high rate is a strong prior, not a verdict — it informs
    confidence, it never auto-decides true/false positive on its own."""
    return _get_fp_signal(rule_uuid, host)


@tool
def thehive_fp_history(rule_uuid: str, host: str, limit: int = 3) -> list:
    """Pull the actual reasoning text behind past closures of this rule/host
    combo from TheHive — only useful, and only actually queried, when
    get_fp_signal showed a long_term_fp_rate > 0.5 with >= 5 samples (enough
    to trust). Below that threshold this returns [] without touching TheHive,
    so calling it speculatively costs nothing."""
    return _thehive_fp_history(rule_uuid, host, limit)


# Per-agent tool lists (SOC-3s-ARCHITECTURE-v3-final.md §1/§6/§7a/§8/§13 Phase
# C/G): no tool appears in both. Agent 1 (perceive) owns open-case
# correlation, MITRE tag extraction, and FP-history signal; Agent 2
# (investigate) owns closed-case history, telemetry, and enrichment.
PERCEPTION_TOOLS = [
    get_fp_signal,
    thehive_fp_history,
    detection_rule_lookup,
    qdrant_retrieve_mitre,
    thehive_open_cases,
    get_case_full,
]

INVESTIGATION_TOOLS = [
    thehive_search_closed,
    elasticsearch_query,
    itop_asset_lookup,
    qdrant_retrieve,
    cortex_analyze,
]

_perception_names = {t.name for t in PERCEPTION_TOOLS}
_investigation_names = {t.name for t in INVESTIGATION_TOOLS}
_overlap = _perception_names & _investigation_names
assert not _overlap, f"Tool overlap between PERCEPTION_TOOLS and INVESTIGATION_TOOLS: {_overlap}"
