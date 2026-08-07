from __future__ import annotations

from typing import Optional

from langchain_core.tools import tool

from tools.cortex import analyze_observable as _cortex_analyze
from tools.detection_rules import get_rule_source as _detection_rule
from tools.elasticsearch import query_related_alerts, query_process_history, query_connection_history
from tools.fp_tracking import get_fp_signal as _get_fp_signal, thehive_fp_history as _thehive_fp_history
from tools.itop import lookup_asset as _itop_lookup
from tools.qdrant import retrieve_mitre, retrieve_playbooks, retrieve_cve
from tools.thehive import search_open_cases, search_closed_cases, get_case_full as _get_case_full


# Every tool argument below is typed Optional and normalized here rather than
# relying on the declared default. An LLM routinely emits an explicit JSON
# `null` for an argument it has no value for, and @tool derives its validation
# schema from these annotations — so a non-Optional `str = ""` rejects null
# during schema validation, before the function body ever runs, and the model
# gets a validation error back instead of a result. Confirmed live: Agent 2
# called elasticsearch_query with user=None and got
# "user: Input should be a valid string" instead of a query.
def _s(value: Optional[str]) -> str:
    return value if isinstance(value, str) else ""


def _i(value: Optional[int], default: int) -> int:
    return value if isinstance(value, int) else default


def _csv(value: Optional[str]) -> list[str]:
    return [s.strip() for s in _s(value).split(",") if s.strip()]


@tool
def cortex_analyze(observable_type: Optional[str] = None, observable_value: Optional[str] = None) -> dict:
    """Run threat intelligence on an observable (ip, domain, url, hash). Returns verdict with score."""
    observable_type, observable_value = _s(observable_type), _s(observable_value)
    if not observable_type or not observable_value:
        return {"error": "cortex_analyze requires both observable_type and observable_value"}
    return _cortex_analyze(observable_type, observable_value)


@tool
def itop_asset_lookup(hostname: Optional[str] = None) -> dict:
    """Look up asset context from iTop CMDB by hostname or IP address.
    Pass the hostname or IP as 'hostname' parameter.
    Returns criticality, owner, department, services, network_zone."""
    hostname = _s(hostname)
    if not hostname:
        return {"found": False, "error": "itop_asset_lookup requires a hostname"}
    return _itop_lookup(hostname)


@tool
def elasticsearch_query(
    index_type: Optional[str] = None,
    host: Optional[str] = None,
    user: Optional[str] = None,
    iocs: Optional[str] = None,
    window_hours: Optional[int] = None,
) -> list:
    """Query Elasticsearch for recent security events.
    index_type: 'alerts' (default), 'process', or 'connections'.
    host: filter by hostname or IP.
    user: filter by username.
    iocs: comma-separated IOCs for alert search.
    window_hours: lookback window (default 24).
    Omit any filter you don't need — omitted/null arguments are ignored, they
    are not treated as an empty-string match.
    """
    index_type = _s(index_type) or "alerts"
    host, user = _s(host), _s(user)
    ioc_list = _csv(iocs)
    window_hours = _i(window_hours, 24)

    if index_type == "alerts":
        return query_related_alerts(host=host or None, user=user or None, iocs=ioc_list or None, window_hours=window_hours)
    elif index_type == "process":
        return query_process_history(host=host or None, user=user or None, window_hours=window_hours)
    elif index_type == "connections":
        src = ioc_list[0] if len(ioc_list) > 0 else host
        dst = ioc_list[1] if len(ioc_list) > 1 else None
        return query_connection_history(src_ip=src or None, dst_ip=dst, window_hours=window_hours)
    return []


@tool
def thehive_search_closed(observables: Optional[str] = None, rule_uuid: Optional[str] = None) -> list:
    """Search TheHive for resolved/closed cases — "has this rule fired before,
    what happened?" observables is a comma-separated list of IOC *values* only
    (IPs, domains, hashes) — never a command line, file path, or free-text
    sentence; those match nothing and waste the call.
    Agent 2 only — open-case correlation is Agent 1's job (thehive_open_cases)."""
    return search_closed_cases(rule_uuid=_s(rule_uuid) or None, observables=_csv(observables) or None)


@tool
def detection_rule_lookup(rule_uuid: Optional[str] = None, source_engine: Optional[str] = None) -> dict:
    """Look up a detection rule's source and MITRE ATT&CK metadata by UUID.
    Single query against Security Onion's so-detection Elasticsearch index,
    which holds the native rule source for all three engines (Sigma,
    Suricata, YARA) — call this FIRST for MITRE mapping, before
    qdrant_retrieve_mitre. source_engine is optional and only a hint; the
    index's own so_detection.language field is authoritative regardless of
    what you pass. Coverage: Sigma rules return a populated `mitre_attack`
    list ~86% of the time; Suricata ~50% (many legitimately have no MITRE
    metadata at all — not an error). YARA never returns MITRE data — it has
    no native tagging convention — but still returns title/description/
    author. Use qdrant_retrieve_mitre as the fallback when this comes back
    with no usable mitre_attack entries."""
    rule_uuid = _s(rule_uuid)
    if not rule_uuid:
        return {"found": False, "error": "detection_rule_lookup requires a rule_uuid"}
    return _detection_rule(rule_uuid, _s(source_engine) or None)


@tool
def qdrant_retrieve(collection: Optional[str] = None, query_text: Optional[str] = None, top_k: Optional[int] = None) -> list:
    """Search Qdrant vector DB for playbooks or CVEs. collection: 'playbooks' or
    'cve'. Returns relevant matches with scores. For MITRE technique search,
    that's Agent 1's tool (qdrant_retrieve_mitre) — not available here."""
    collection, query_text = _s(collection), _s(query_text)
    if not query_text:
        return []
    top_k = _i(top_k, 5)
    if collection == "playbooks":
        return retrieve_playbooks(query_text, top_k)
    elif collection == "cve":
        return retrieve_cve(query_text, top_k)
    return []


@tool
def qdrant_retrieve_mitre(query_text: Optional[str] = None, top_k: Optional[int] = None) -> list:
    """Search Qdrant for candidate MITRE ATT&CK techniques matching a description
    of the alert's behavior (rule name, description, command line, etc). Use this
    when no explicit MITRE tags are available from detection_rule_lookup."""
    query_text = _s(query_text)
    if not query_text:
        return []
    return retrieve_mitre(query_text, _i(top_k, 5))


@tool
def thehive_open_cases(observables: Optional[str] = None, host: Optional[str] = None, user: Optional[str] = None) -> list:
    """Search TheHive for open/in-progress cases sharing an observable, host, or
    user with this alert. observables is a comma-separated list of IOC *values*
    only (IPs/domains/hashes) — not command lines or free text. Omit any filter
    you don't need rather than passing an empty value."""
    return search_open_cases(
        observables=_csv(observables) or None,
        host=_s(host) or None,
        user=_s(user) or None,
    )


@tool
def get_case_full(case_id: Optional[str] = None) -> dict:
    """Fetch full content (description, severity, tags, metrics, custom fields,
    summary) of a specific TheHive case by ID. Call this AFTER thehive_open_cases
    finds a candidate case, to read its actual content before deciding merge vs
    new — thehive_open_cases only returns a shallow list, not enough to reason
    about match strength or kill-chain progression on its own."""
    case_id = _s(case_id)
    if not case_id:
        return {"found": False, "error": "get_case_full requires a case_id"}
    result = _get_case_full(case_id)
    return result or {"found": False, "case_id": case_id}


@tool
def get_fp_signal(rule_uuid: Optional[str] = None, host: Optional[str] = None) -> dict:
    """Check this rule/host combo's historical false-positive rate before
    investigating further — instant, local, always call this FIRST. Returns
    short_term (24h) and long_term (30d) fp_rate + total sample count for
    each window. A high rate is a strong prior, not a verdict — it informs
    confidence, it never auto-decides true/false positive on its own."""
    return _get_fp_signal(_s(rule_uuid), _s(host))


@tool
def thehive_fp_history(rule_uuid: Optional[str] = None, host: Optional[str] = None, limit: Optional[int] = None) -> list:
    """Pull the actual reasoning text behind past closures of this rule/host
    combo from TheHive — only useful, and only actually queried, when
    get_fp_signal showed a long_term_fp_rate > 0.5 with >= 5 samples (enough
    to trust). Below that threshold this returns [] without touching TheHive,
    so calling it speculatively costs nothing."""
    return _thehive_fp_history(_s(rule_uuid), _s(host), _i(limit, 3))


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
