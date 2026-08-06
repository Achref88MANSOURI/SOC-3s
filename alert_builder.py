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
    """so-ioc-normalize sets ioc.source_engine = event.module for every engine
    (Sigma/Suricata/YARA all funnel through this same final_pipeline) — confirmed
    from Security Onion's own pipeline source, not inferred. event.module is the
    same value one level up in case the ioc.* wrapper hasn't run yet. type/tags
    are legacy fallbacks for non-raw-SO-shaped callers (e.g. a TheHive-alert-shaped
    raw_alert), kept for defense, not expected to fire on real SO payloads."""
    ioc = _as_dict(raw_alert.get("ioc"))
    engine = (ioc.get("source_engine") or "").lower()
    if engine:
        return engine
    engine = (_as_dict(raw_alert.get("event")).get("module") or "").lower()
    if engine:
        return engine
    engine = (raw_alert.get("type") or "").lower()
    if engine:
        return engine
    for tag in raw_alert.get("tags", []) or []:
        if not isinstance(tag, str):
            continue
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
        native_severity=_native_severity(raw_alert),
    )


def _native_severity(raw_alert: dict) -> int:
    """event.severity is the cross-engine-normalized field (confirmed via
    Security Onion's common/common.nids/so-ioc-normalize pipelines — Suricata's
    own rule.severity is pre-normalization and inverted, 1=highest, so it's
    deliberately NOT used here). Top-level severity is a defensive fallback for
    non-raw-SO-shaped callers only."""
    value = raw_alert.get("severity")
    if isinstance(value, int):
        return value
    event_severity = _as_dict(raw_alert.get("event")).get("severity")
    if isinstance(event_severity, int):
        return event_severity
    return 2


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


def _extract_winlog_host(event_data: dict) -> Host | None:
    """Native Windows Event Log (winlog) channel — a distinct telemetry shape
    from the Elastic-Defend/Sysmon-via-elastic-agent one _extract_host_from_event_data
    handles. Confirmed field (live logs-detections.alerts-so field mapping,
    reference.txt): event_data.winlog.computer_name. Sigma rules matching
    native winlog channels (as opposed to Sysmon-derived process events) carry
    this instead of event_data.host.*."""
    winlog = _as_dict(event_data.get("winlog"))
    computer_name = winlog.get("computer_name")
    if not computer_name:
        return None
    return Host(hostname=computer_name)


def _extract_winlog_user(event_data: dict) -> User | None:
    """Confirmed fields: event_data.winlog.user.{name,identifier} (identifier
    is a Windows SID, mapped to User.id the same way _extract_user_from_event_data
    maps event_data.user.id)."""
    winlog = _as_dict(event_data.get("winlog"))
    user_data = _as_dict(winlog.get("user"))
    name = user_data.get("name")
    if not name:
        return None
    identifier = user_data.get("identifier")
    return User(name=name, id=str(identifier) if identifier is not None else None)


def _extract_winlog_process(event_data: dict) -> Process | None:
    """Confirmed field: event_data.winlog.process.pid only. The live field
    mapping this was verified against (reference.txt) does not show an
    Image/CommandLine/Name equivalent under this shape — event_data.winlog.
    event_data.{Company,Description,FileVersion,Product,...} look like
    PE-version-resource metadata (the same kind of fields Sysmon's own
    event_data.process.pe.* carries) but Process has no field for them and
    there isn't enough confirmed structure here to say which specific winlog
    event type produces this shape, so they're deliberately left unmapped
    rather than guessed at."""
    winlog = _as_dict(event_data.get("winlog"))
    process_data = _as_dict(winlog.get("process"))
    pid = process_data.get("pid")
    if pid is None:
        return None
    return Process(pid=pid)


def _extract_powershell_from_event_data(event_data: dict) -> Process | None:
    """PowerShell engine-lifecycle logging (Microsoft-Windows-PowerShell/
    Operational channel — a winlog sub-shape, but with its own dedicated
    event_data.powershell.* namespace). Confirmed fields: event_data.
    powershell.engine.{new_state,previous_state,version},
    event_data.powershell.process.executable_version,
    event_data.powershell.runspace_id. No pid/command_line/name exist for
    this shape — it's an engine state-change event, not a spawned process —
    synthesized into command_line the same way as SSH/HTTP below."""
    powershell = _as_dict(event_data.get("powershell"))
    engine = _as_dict(powershell.get("engine"))
    new_state = engine.get("new_state")
    previous_state = engine.get("previous_state")
    if not (new_state or previous_state):
        return None
    summary = f"powershell engine {previous_state or '?'} -> {new_state or '?'}"
    version = _as_dict(powershell.get("process")).get("executable_version")
    if version:
        summary += f" (v{version})"
    return Process(command_line=summary)


def _extract_ssh_auth_from_event_data(event_data: dict) -> Process | None:
    """SSH auth log lines (Filebeat system/auth module) carry no process
    telemetry at all — confirmed fields: event_data.system.auth.ssh.{event,
    method} (e.g. event="Accepted", method="publickey"). There is no typed
    CanonicalAlert field for an authentication outcome, so this is synthesized
    into command_line as a short textual description — the same "best
    available descriptive text, not necessarily a literal shell invocation"
    precedent _parse_process's description-regex fallback already uses."""
    ssh = _as_dict(_as_dict(_as_dict(event_data.get("system")).get("auth")).get("ssh"))
    event = ssh.get("event")
    if not event:
        return None
    method = ssh.get("method")
    summary = f"ssh {event}" + (f" ({method})" if method else "")
    return Process(command_line=summary)


def _extract_http_login_flow_from_event_data(event_data: dict) -> Process | None:
    """Kratos/identity-provider auth-flow logging (an HTTP-request-driven
    Sigma match, not host telemetry) — confirmed fields: event_data.http.
    {method,uri,useragent}, event_data.login_flow.{type,state}. Same
    synthesized-command_line approach as _extract_ssh_auth_from_event_data,
    for the same reason: no process exists here, but the request
    method/uri/login-flow state is the actual rule-relevant content."""
    http = _as_dict(event_data.get("http"))
    login_flow = _as_dict(event_data.get("login_flow"))
    method = http.get("method")
    uri = http.get("uri")
    if not (method or uri):
        return None
    summary = " ".join(p for p in (method, uri) if p)
    flow_type = login_flow.get("type")
    flow_state = login_flow.get("state")
    if flow_type or flow_state:
        summary += f" [login_flow type={flow_type or '?'} state={flow_state or '?'}]"
    return Process(command_line=summary)


def _split_host_port(value: str) -> tuple[str, int | None]:
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        if port.isdigit():
            return host, int(port)
    return value, None


def _extract_network_from_event_data(event_data: dict) -> Network | None:
    """Network context nested under event_data rather than raw_alert's top
    level — used by _extract_network_from_raw_alert's callers as a fallback
    for the auth-log/HTTP shapes above, which carry a connecting source
    address but no Suricata-style top-level source/destination. Confirmed
    fields: event_data.source.{ip,address,port} (SSH auth logs) and
    event_data.http.request.remote (Kratos/HTTP request source — a
    "host[:port]" string per the field mapping, port split off defensively
    since the mapping only confirms it as an opaque keyword string)."""
    source = _as_dict(event_data.get("source"))
    src_ip = source.get("ip") or source.get("address")
    src_port = source.get("port")
    if not src_ip:
        http = _as_dict(event_data.get("http"))
        request = _as_dict(http.get("request"))
        remote = request.get("remote")
        if remote:
            src_ip, src_port = _split_host_port(remote)
    if not src_ip:
        return None
    return Network(src_ip=src_ip, src_port=src_port)


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
    event_data — confirmed: file.name, file.path, file.mime_type (renamed from
    file.flavors.mime). Hashes are NOT nested under file.hash — Security Onion's
    own strelka.file ingest pipeline renames scan.hash to a top-level `hash`
    field, sibling of `file`, not nested under it (confirmed from so-ingest-
    reference). file.hash is checked too, defensively, in case a differently-
    shaped caller nests it there. No process/user/network fields are guaranteed
    for these alerts."""
    file_data = _as_dict(raw_alert.get("file"))
    hashes = HashBundle()
    if not file_data:
        return None, hashes

    hash_data = _as_dict(raw_alert.get("hash")) or _as_dict(file_data.get("hash"))
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
    """@timestamp (ISO8601) is the real raw-SO-doc field — confirmed universal
    across the live logs-detections.alerts-so mapping and every ingest pipeline
    reviewed (all standardize on it as the ECS timestamp field). `date` (epoch-ms)
    is kept as a fallback for non-raw-SO-shaped callers only."""
    raw_ts = raw_alert.get("@timestamp")
    if isinstance(raw_ts, str):
        try:
            return datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except ValueError:
            pass
    date_ms = raw_alert.get("date")
    if isinstance(date_ms, (int, float)):
        return datetime.fromtimestamp(date_ms / 1000, tz=timezone.utc)
    return datetime.now(timezone.utc)


def _build_observables(hive_alert: dict | None) -> Observables:
    """Raw SO alert docs never carry an `observables` list at all — that's purely
    a TheHive concept. The curated, IOC-flagged, Cortex-scored list only exists
    on hive_alert (n8n's Alert Builder created these observables and Cortex
    already scored them before /triage was ever called) — so this reads from
    hive_alert, not raw_alert. See _extract_ioc_indicators for the supplementary
    raw_alert-derived recovery pass."""
    external_ips: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    hashes = HashBundle()

    for obs in (hive_alert or {}).get("observables", []) or []:
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


def _extract_ioc_indicators(raw_alert: dict) -> Observables:
    """Security Onion's own so-ioc-normalize final_pipeline computes ioc.indicators
    directly on raw_alert, before Cortex or n8n ever see it — engine-agnostic,
    confirmed from SO's pipeline source. It's rich for Suricata/network alerts
    (source.ip/destination.ip/dns.question.name/url.full are already top-level
    ECS fields by the time that pipeline runs) and typically empty for
    process-creation Sigma alerts, since that pipeline never looks inside
    event_data. Supplementary to hive_alert's curated list, not a replacement —
    catches IOCs SO itself derived that n8n's extraction might not have flagged."""
    ioc = _as_dict(raw_alert.get("ioc"))
    external_ips: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    hashes = HashBundle()

    for ind in ioc.get("indicators", []) or []:
        if not isinstance(ind, dict):
            continue
        itype = ind.get("type", "")
        value = ind.get("value", "")
        if not value:
            continue
        if itype == "ip":
            external_ips.append(value)
        elif itype == "domain":
            domains.append(value)
        elif itype == "url":
            urls.append(value)
        elif itype.startswith("hash_"):
            algo = itype.split("_", 1)[1]
            if algo in _HASH_FIELDS:
                getattr(hashes, algo).append(value)

    return Observables(external_ips=external_ips, domains=domains, urls=urls, hashes=hashes)


def _merge_observables(target: Observables, extra: Observables) -> None:
    for field in ("external_ips", "domains", "urls"):
        existing = getattr(target, field)
        for value in getattr(extra, field):
            if value not in existing:
                existing.append(value)
    _merge_hashes(target.hashes, extra.hashes)


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
    - Sigma: raw_alert["event_data"] carries the matched source event, in one
      of (at least) five confirmed shapes depending on which underlying log
      source the rule matched — checked in this order: Elastic-Defend/Sysmon
      process events (_extract_process_from_event_data /
      _extract_host_from_event_data / _extract_user_from_event_data), native
      Windows Event Log winlog events (_extract_winlog_*), PowerShell
      engine-lifecycle events (_extract_powershell_from_event_data), SSH auth
      log lines (_extract_ssh_auth_from_event_data), and Kratos/HTTP
      login-flow events (_extract_http_login_flow_from_event_data) — the
      latter three have no process telemetry at all, so their result is a
      short synthesized command_line description, not a literal shell
      invocation.
    - Suricata: no event_data; network context (source/destination ip/port,
      transport) lives at the top level of raw_alert — see
      _extract_network_from_raw_alert. No process/user/hash fields exist.
    - YARA/Strelka: no event_data; file context (name, path, hashes) lives at
      the top level of raw_alert — see _extract_file_from_raw_alert. No
      process/user/network fields are guaranteed.
    Observables (IPs/domains/URLs/hashes) come from hive_alert, not raw_alert —
    raw SO alert docs never carry an observables list, only TheHive does (see
    _build_observables). _extract_ioc_indicators supplements this from
    raw_alert's own ioc.indicators, which Security Onion computes itself
    directly on the alert (rich for network/Suricata alerts, typically empty
    for process-creation Sigma alerts).
    Every extractor degrades to None/empty on missing fields rather than
    raising — regexing the description string is the final fallback for
    rule/host identity when no structured field is present. Agent 1 fills any
    remaining gaps."""
    description = raw_alert.get("description", "") or ""
    source_engine = _source_engine(raw_alert)
    event_data = _as_dict(raw_alert.get("event_data"))

    cortex_results, observable_ids = _build_cortex_results(hive_alert)
    observables = _build_observables(hive_alert)
    _merge_observables(observables, _extract_ioc_indicators(raw_alert))

    host = (
        _extract_host_from_event_data(event_data)
        or _extract_winlog_host(event_data)
        or _parse_host(raw_alert, description)
    )
    user = _extract_user_from_event_data(event_data) or _extract_winlog_user(event_data)
    process, event_data_hashes = _extract_process_from_event_data(event_data)
    if process is None:
        process = _extract_winlog_process(event_data)
    if process is None:
        process = _extract_powershell_from_event_data(event_data)
    if process is None:
        process = _extract_ssh_auth_from_event_data(event_data)
    if process is None:
        process = _extract_http_login_flow_from_event_data(event_data)
    if process is None:
        process = _parse_process(description)
    network = _extract_network_from_raw_alert(raw_alert) or _extract_network_from_event_data(event_data)
    file_, file_hashes = _extract_file_from_raw_alert(raw_alert)

    _merge_hashes(observables.hashes, event_data_hashes)
    _merge_hashes(observables.hashes, file_hashes)

    return CanonicalAlert(
        alert_id=(
            thehive_alert_id
            or raw_alert.get("sourceRef", "")
            or raw_alert.get("_id", "")
            or raw_alert.get("title", "unknown")
        ),
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
