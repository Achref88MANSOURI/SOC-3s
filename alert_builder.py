from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from schemas import (
    CanonicalAlert,
    CortexResult,
    HashBundle,
    Host,
    Network,
    Observables,
    Process,
    Rule,
    User,
)

# A value starting with http(s):// is always a URL regardless of what n8n's
# Alert Builder node stamped as dataType (known mis-classification — see
# SOC-3s-ARCHITECTURE-v2.md §3).
URL_RE = re.compile(r"^https?://", re.IGNORECASE)

RULE_RE = re.compile(r"Rule:\s*(.+?)\s*\(([0-9a-fA-F-]{8,})\)")
HOST_RE = re.compile(r"Host:\s*(\S+)\s*\(([\d.]+)\)")
COMMAND_LINE_RE = re.compile(r"Command line:\s*(.+)", re.DOTALL)
ENGINE_TAG_RE = re.compile(r"^engine:(\w+)", re.IGNORECASE)

PROFILE_BY_ENGINE = {
    "suricata": "network_threat",
    "yara": "malicious_file",
    "sigma": "endpoint_behavior",
}

_LEVEL_SCORES = {"malicious": 90, "suspicious": 55, "safe": 5, "info": 0}
_LEVEL_TO_VERDICT = {"malicious": "malicious", "suspicious": "suspicious", "safe": "clean"}

_HASH_FIELDS = {"md5", "sha1", "sha256", "sha512", "imphash"}


def _classify_observable_type(data_type: str, value: str) -> str:
    if URL_RE.match(value or ""):
        return "url"
    data_type = (data_type or "").lower()
    if data_type in ("ip", "ip-src", "ip-dst"):
        return "ip"
    if data_type == "fqdn":
        return "domain"
    return data_type


def _source_engine(raw_alert: dict) -> str:
    engine = (raw_alert.get("type") or "").lower()
    if engine:
        return engine
    for tag in raw_alert.get("tags", []) or []:
        m = ENGINE_TAG_RE.match(tag)
        if m:
            return m.group(1).lower()
    return "unknown"


def _parse_rule(raw_alert: dict, description: str) -> Rule:
    name = ""
    uuid = ""
    m = RULE_RE.search(description)
    if m:
        name, uuid = m.group(1).strip(), m.group(2).strip()
    if not name:
        for tag in raw_alert.get("tags", []) or []:
            if tag.lower().startswith("rule:"):
                name = tag.split(":", 1)[1].strip()
                break
    if not name:
        name = raw_alert.get("title", "") or "unknown"
    return Rule(
        name=name,
        uuid=uuid,
        native_severity=raw_alert.get("severity", 2),
    )


def _parse_host(raw_alert: dict, description: str) -> Host | None:
    m = HOST_RE.search(description)
    if m:
        return Host(hostname=m.group(1), ip=[m.group(2)])
    for tag in raw_alert.get("tags", []) or []:
        if re.match(r"^[a-zA-Z0-9-]+$", tag) and "-" in tag and "engine:" not in tag and "rule:" not in tag:
            # Bare hostname-shaped tag (e.g. "win-kvkmd51ggkq") — best-effort fallback.
            return Host(hostname=tag)
    return None


def _parse_process(description: str) -> Process | None:
    m = COMMAND_LINE_RE.search(description)
    if not m:
        return None
    return Process(command_line=m.group(1).strip())


def _parse_timestamp(raw_alert: dict) -> datetime:
    date_ms = raw_alert.get("date")
    if isinstance(date_ms, (int, float)):
        return datetime.fromtimestamp(date_ms / 1000, tz=timezone.utc)
    return datetime.now(timezone.utc)


def _build_observables(raw_alert: dict) -> Observables:
    external_ips: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    hashes = HashBundle()

    for obs in raw_alert.get("observables", []) or []:
        value = obs.get("data", "")
        if not value:
            continue
        obs_type = _classify_observable_type(obs.get("dataType", ""), value)

        if obs_type == "ip":
            external_ips.append(value)
        elif obs_type == "domain":
            domains.append(value)
        elif obs_type == "url":
            urls.append(value)
        elif obs_type == "hash":
            tag = next(
                (t.lower() for t in (obs.get("tags") or []) if t.lower() in _HASH_FIELDS),
                None,
            )
            if tag:
                getattr(hashes, tag).append(value)
            # Unrecognized hash tag: leave it out rather than guess the wrong
            # bucket — Agent 1 (perceive) fills this gap with LLM reasoning.

    return Observables(external_ips=external_ips, domains=domains, urls=urls, hashes=hashes)


def _summarize_taxonomies(taxonomies: list[dict]) -> tuple[str, int, str]:
    if not taxonomies:
        return "unknown", 0, ""
    worst = max(taxonomies, key=lambda t: _LEVEL_SCORES.get(t.get("level"), 0))
    level = worst.get("level")
    verdict = _LEVEL_TO_VERDICT.get(level, "unknown")
    score = _LEVEL_SCORES.get(level, 0)
    details = "; ".join(
        f"{t.get('namespace')}:{t.get('predicate')}={t.get('value')} ({t.get('level')})"
        for t in taxonomies
    )
    return verdict, score, details


def _build_cortex_results(hive_alert: dict | None) -> tuple[list[CortexResult], dict[str, Any]]:
    cortex_results: list[CortexResult] = []
    observable_ids: dict[str, Any] = {}

    for obs in (hive_alert or {}).get("observables", []) or []:
        obs_id = obs.get("_id", "")
        obs_data = obs.get("data", "")
        obs_type = obs.get("dataType", "")
        if obs_id and obs_data:
            observable_ids[obs_data] = obs_id

        for analyzer_name, report in (obs.get("reports") or {}).items():
            taxonomies = (report.get("summary") or {}).get("taxonomies", [])
            if not taxonomies:
                continue
            verdict, score, details = _summarize_taxonomies(taxonomies)
            cortex_results.append(CortexResult(
                observable=obs_data,
                type=obs_type,
                verdict=verdict,
                score=score,
                details=details,
                analyzer=analyzer_name,
                raw=report,
            ))

    return cortex_results, observable_ids


def build_canonical_alert(
    raw_alert: dict,
    hive_alert: dict | None,
    asset_context: dict,
    thehive_alert_id: str = "",
) -> CanonicalAlert:
    """Deterministic, best-effort assembly of a CanonicalAlert from n8n's slim
    payload. This is NOT the LLM normalization step (that's Agent 1 / perceive,
    Phase 3) — it's the pre-LLM structural pass described in
    SOC-3s-ARCHITECTURE-v2.md §4 sub-task 1. Fields it can't confidently parse
    (user, network, file for most engines) are left None; Agent 1 fills gaps."""
    description = raw_alert.get("description", "") or ""
    source_engine = _source_engine(raw_alert)

    cortex_results, observable_ids = _build_cortex_results(hive_alert)

    return CanonicalAlert(
        alert_id=thehive_alert_id or raw_alert.get("sourceRef", "") or raw_alert.get("title", "unknown"),
        timestamp=_parse_timestamp(raw_alert),
        source_engine=source_engine,
        investigation_profile=PROFILE_BY_ENGINE.get(source_engine, "generic"),
        rule=_parse_rule(raw_alert, description),
        host=_parse_host(raw_alert, description),
        user=None,
        network=None,
        process=_parse_process(description),
        file=None,
        observables=_build_observables(raw_alert),
        cortex_results=cortex_results,
        asset_context=asset_context or {},
        thehive_alert_id=thehive_alert_id,
        thehive_observable_ids=observable_ids,
    )
