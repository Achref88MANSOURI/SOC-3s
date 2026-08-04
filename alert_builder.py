from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from schemas import (
    CanonicalAlert,
    CortexResult,
    File,
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
# SOC-3s-ARCHITECTURE-v3-final.md §5).
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


def _as_dict(value: Any) -> dict:
    """A field expected to be a nested object may collide with an unrelated
    top-level field of the same name that's actually a string (e.g. n8n's
    envelope has a top-level `source` string — the source *system* — which
    collides with Suricata's ECS `source` object, network source ip/port).
    Used everywhere a raw_alert/event_data sub-object is read, so a shape
    surprise degrades to "field absent" instead of an AttributeError."""
    return value if isinstance(value, dict) else {}


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
    """Structured path first: Suricata and YARA/Strelka alerts carry a top-level
    `rule` dict (confirmed from live payloads) — `rule.name`/`rule.uuid`, where
    Suricata's uuid is the SID as a string and YARA's uuid equals its rule name
    (Security Onion's own strelka.file ingest pipeline sets `rule.uuid =
    rule.name` — there's no separate YARA rule ID). Sigma alerts don't carry
    this top-level dict, so this falls through to the existing description/tag
    parsing for them, unchanged."""
    rule_data = _as_dict(raw_alert.get("rule"))
    name = rule_data.get("name") or ""
    uuid = rule_data.get("uuid") or ""

    if not name:
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
        uuid=str(uuid) if uuid else "",
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


def _extract_host_from_event_data(event_data: dict) -> Host | None:
    host_data = _as_dict(event_data.get("host"))
    hostname = host_data.get("hostname") or host_data.get("name")
    if not hostname:
        return None
    return Host(hostname=hostname, ip=host_data.get("ip") or [], os=_as_dict(host_data.get("os")))


def _extract_user_from_event_data(event_data: dict) -> User | None:
    user_data = _as_dict(event_data.get("user"))
    name = user_data.get("name")
    if not name:
        return None
    user_id = user_data.get("id")
    return User(name=name, id=str(user_id) if user_id is not None else None)


def _extract_process_from_event_data(event_data: dict) -> tuple[Process | None, HashBundle]:
    """event_data is the embedded source event a Sigma/ElastAlert2 alert matched
    against. Confirmed field paths, from live captured payloads across this
    project: event_data.process.{name,executable,command_line,pid,
    working_directory}, event_data.process.parent.{name,command_line,pid},
    event_data.process.hash.{sha256,md5}, event_data.process.pe.imphash,
    event_data.host.*, event_data.user.*. Every field is genuinely optional —
    which ones are populated depends on which Sigma rule fired and what
    telemetry it matched, not just which OS/agent produced it; nothing here
    assumes any single field is always present.

    Two extra fallback locations are also checked defensively and are NOT
    independently confirmed live: a top-level event_data.hash.* (in addition to
    the confirmed process.hash.*), and process.ppid (in addition to the
    confirmed process.parent.pid). Security Onion's own sysmon ingest pipeline
    (salt/elasticsearch/files/ingest/sysmon) names fields this way for at least
    one telemetry path — kept as harmless additional coverage, not a hard
    requirement, since every lookup here degrades to None rather than raising.
    """
    process_data = _as_dict(event_data.get("process"))
    hashes = HashBundle()
    if not process_data:
        return None, hashes

    parent = _as_dict(process_data.get("parent"))
    hash_data = _as_dict(process_data.get("hash")) or _as_dict(event_data.get("hash"))
    pe = _as_dict(process_data.get("pe"))

    for field in ("md5", "sha1", "sha256", "sha512"):
        value = hash_data.get(field)
        if value:
            getattr(hashes, field).append(value)
    imphash = pe.get("imphash") or hash_data.get("imphash")
    if imphash:
        hashes.imphash.append(imphash)

    command_line = process_data.get("command_line")
    name = process_data.get("name")
    path = process_data.get("executable")
    if not (command_line or name or path):
        return None, hashes

    parent_pid = parent.get("pid")
    if parent_pid is None:
        parent_pid = process_data.get("ppid")  # Sysmon convention, see docstring

    process = Process(
        pid=process_data.get("pid"),
        name=name,
        path=path,
        command_line=command_line,
        working_directory=process_data.get("working_directory"),
        parent_pid=parent_pid,
        parent_name=parent.get("name"),  # Elastic Defend only; None for Sysmon
        parent_command_line=parent.get("command_line"),
    )
    return process, hashes


def _merge_hashes(target: HashBundle, extra: HashBundle) -> None:
    for field in ("md5", "sha1", "sha256", "sha512", "imphash"):
        existing = getattr(target, field)
        for value in getattr(extra, field):
            if value not in existing:
                existing.append(value)


def _extract_network_from_raw_alert(raw_alert: dict) -> Network | None:
    """Suricata alerts carry network context at the top level, not under
    event_data — confirmed: source.ip/destination.ip (some pipeline paths use
    src_ip/dest_ip instead, checked as a fallback), source.port/destination.port,
    network.transport. No process/user/hash fields exist for Suricata alerts at
    all — this is network context only.

    Note: n8n's Alert Builder envelope also has a top-level `source` key, but
    as a plain string (the source *system*, e.g. "security-onion") — not
    Suricata's ECS `source` object (network source ip/port). Guarded with an
    isinstance check so that envelope shape doesn't crash this extractor."""
    source = raw_alert.get("source")
    source = source if isinstance(source, dict) else {}
    destination = raw_alert.get("destination")
    destination = destination if isinstance(destination, dict) else {}
    network_meta = raw_alert.get("network")
    network_meta = network_meta if isinstance(network_meta, dict) else {}

    src_ip = source.get("ip") or raw_alert.get("src_ip")
    dst_ip = destination.get("ip") or raw_alert.get("dest_ip") or raw_alert.get("dst_ip")
    if not (src_ip or dst_ip):
        return None

    return Network(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=source.get("port"),
        dst_port=destination.get("port"),
        protocol=network_meta.get("transport"),
    )


def _extract_file_from_raw_alert(raw_alert: dict) -> tuple[File | None, HashBundle]:
    """YARA/Strelka alerts carry file context at the top level, not under
    event_data — confirmed: file.name, file.path, file.hash.md5,
    file.hash.sha256. No process/user/network fields are guaranteed for these
    alerts."""
    file_data = _as_dict(raw_alert.get("file"))
    hashes = HashBundle()
    if not file_data:
        return None, hashes

    hash_data = _as_dict(file_data.get("hash"))
    for field in ("md5", "sha1", "sha256", "sha512"):
        value = hash_data.get(field)
        if value:
            getattr(hashes, field).append(value)

    name = file_data.get("name")
    path = file_data.get("path")
    if not (name or path or hash_data):
        return None, hashes

    return File(
        name=name,
        path=path,
        size=file_data.get("size"),
        mime_type=file_data.get("mime_type"),
    ), hashes


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
    SOC-3s-ARCHITECTURE-v3-final.md §5.

    Per-engine structured extraction, all confirmed from live captured payloads
    and Security Onion's own ingest pipeline source (so-ingest-reference/):
    - Sigma: raw_alert["event_data"] carries the matched source event — see
      _extract_process_from_event_data / _extract_host_from_event_data /
      _extract_user_from_event_data.
    - Suricata: no event_data; network context (source/destination ip/port,
      transport) lives at the top level of raw_alert — see
      _extract_network_from_raw_alert. No process/user/hash fields exist.
    - YARA/Strelka: no event_data; file context (name, path, hashes) lives at
      the top level of raw_alert — see _extract_file_from_raw_alert. No
      process/user/network fields are guaranteed.
    Every extractor degrades to None/empty on missing fields rather than
    raising — regexing the description string is the final fallback for
    rule/host identity when no structured field is present. Agent 1 fills any
    remaining gaps."""
    description = raw_alert.get("description", "") or ""
    source_engine = _source_engine(raw_alert)
    event_data = _as_dict(raw_alert.get("event_data"))

    cortex_results, observable_ids = _build_cortex_results(hive_alert)
    observables = _build_observables(raw_alert)

    host = _extract_host_from_event_data(event_data) or _parse_host(raw_alert, description)
    user = _extract_user_from_event_data(event_data)
    process, event_data_hashes = _extract_process_from_event_data(event_data)
    if process is None:
        process = _parse_process(description)
    network = _extract_network_from_raw_alert(raw_alert)
    file_, file_hashes = _extract_file_from_raw_alert(raw_alert)

    _merge_hashes(observables.hashes, event_data_hashes)
    _merge_hashes(observables.hashes, file_hashes)

    return CanonicalAlert(
        alert_id=thehive_alert_id or raw_alert.get("sourceRef", "") or raw_alert.get("title", "unknown"),
        timestamp=_parse_timestamp(raw_alert),
        source_engine=source_engine,
        investigation_profile=PROFILE_BY_ENGINE.get(source_engine, "generic"),
        rule=_parse_rule(raw_alert, description),
        host=host,
        user=user,
        network=network,
        process=process,
        file=file_,
        observables=observables,
        cortex_results=cortex_results,
        asset_context=asset_context or {},
        thehive_alert_id=thehive_alert_id,
        thehive_observable_ids=observable_ids,
    )
