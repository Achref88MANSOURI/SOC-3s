from __future__ import annotations

import re

import requests
import yaml

from tools.elasticsearch import _es_post

# Security Onion indexes the full native source for all three detection
# engines (Sigma, Suricata, YARA) in one index, keyed by so_detection.publicId
# — a UUID for Sigma, the Emerging Threats SID for Suricata, and the rule name
# itself for YARA. This replaces Phase B's filesystem approach: the files
# under /opt/so/rules/elastalert/rules/*.yml are compiled ElastAlert2 output,
# not native Sigma, and strip the MITRE tags: field during compilation — that
# path could never yield MITRE mappings. so-detection has the unmodified
# native source with tags intact.
SO_DETECTION_INDEX = "so-detection"

# Suricata: sid is Emerging Threats' own sequential rule identifier, NOT a
# MITRE technique ID — it's used purely as the lookup key. The real MITRE
# data, when present, lives in the rule's `metadata:` block as key-value
# pairs. Regexes unchanged from Phase B; only the input changed (the
# so_detection.content field string, not a line read from a rules file).
MSG_RE = re.compile(r'msg:"([^"]*)"')
METADATA_RE = re.compile(r"metadata:([^;]*);")

# Sigma tags use four distinct attack.* namespaces (SOC-3s-ARCHITECTURE-v3-final.md,
# live-verified): attack.t#### / attack.t####.### (technique/sub-technique),
# attack.g#### (ATT&CK Group), attack.s#### (ATT&CK Software), and anything
# else under attack.* (tactic — kept as-is, including non-canonical names like
# "stealth" or "defense-impairment" that SigmaHQ uses in practice; techniques
# are the authoritative field, tactics are advisory strings, never validated
# against a hardcoded enum). Tags outside the attack.* namespace entirely
# (e.g. detection.emerging-threats) are ignored.
_TECHNIQUE_RE = re.compile(r"^t(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_GROUP_RE = re.compile(r"^g(\d{4})$", re.IGNORECASE)
_SOFTWARE_RE = re.compile(r"^s(\d{4})$", re.IGNORECASE)


def get_rule_source(rule_uuid: str, source_engine: str | None = None) -> dict:
    """Fetch detection rule source from Security Onion's so-detection index.

    Covers Sigma, Suricata, and YARA — all three live in the same index with
    the same schema. rule_uuid matches so_detection.publicId directly for all
    three engines (UUID / SID string / YARA rule name respectively).

    source_engine is accepted for call-site compatibility but is now only an
    optional HINT — the index tells us the real language via
    so_detection.language, and that is authoritative over the hint. It is not
    used to alter the query or the dispatch.
    """
    try:
        result = _es_post(
            f"/{SO_DETECTION_INDEX}/_search",
            {"query": {"term": {"so_detection.publicId": rule_uuid}}, "size": 1},
        )
    except requests.exceptions.RequestException as e:
        return {"found": False, "error": str(e)}

    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        return {"found": False, "public_id": rule_uuid}

    doc = hits[0].get("_source", {}) or {}
    so_detection = doc.get("so_detection", {}) or {}
    language = (so_detection.get("language") or "").lower()

    base = {
        "found": True,
        "source_engine": language,
        "engine": so_detection.get("engine", ""),
        "public_id": so_detection.get("publicId", rule_uuid),
        "title": so_detection.get("title", ""),
        "description": so_detection.get("description", ""),
        "severity": so_detection.get("severity", ""),
        "author": so_detection.get("author", ""),
        "category": so_detection.get("category", ""),
        "is_enabled": so_detection.get("isEnabled", False),
        "ruleset": so_detection.get("ruleset", ""),
        "product": so_detection.get("product"),
    }

    if language == "sigma":
        extra = _parse_sigma(so_detection)
    elif language == "suricata":
        extra = _parse_suricata(so_detection.get("content", "") or "")
    elif language == "yara":
        extra = _parse_yara()
    else:
        extra = _empty_mitre_fields(note=f"Unrecognized so_detection.language: {language!r}")

    base.update(extra)
    return base


def _empty_mitre_fields(note: str | None = None) -> dict:
    return {
        "mitre_attack": [],
        "mitre_tactics": [],
        "mitre_groups": [],
        "mitre_software": [],
        "mitre_technique_names": [],
        "falsepositives": [],
        "level": None,
        "references": [],
        "note": note,
    }


def _parse_sigma_tags(tags: list) -> dict:
    techniques, tactics, groups, software = [], [], [], []
    for tag in tags:
        if not isinstance(tag, str) or not tag.lower().startswith("attack."):
            continue
        rest = tag[len("attack."):]

        m = _TECHNIQUE_RE.match(rest)
        if m:
            techniques.append("T" + m.group(1).upper())
            continue
        m = _GROUP_RE.match(rest)
        if m:
            groups.append("G" + m.group(1))
            continue
        m = _SOFTWARE_RE.match(rest)
        if m:
            software.append("S" + m.group(1))
            continue
        tactics.append(rest)

    return {
        "mitre_attack": techniques,
        "mitre_tactics": tactics,
        "mitre_groups": groups,
        "mitre_software": software,
    }


def _parse_sigma(so_detection: dict) -> dict:
    content = so_detection.get("content", "") or ""
    try:
        parsed = yaml.safe_load(content) if content else None
    except yaml.YAMLError:
        parsed = None
    parsed = parsed if isinstance(parsed, dict) else {}

    tag_fields = _parse_sigma_tags(parsed.get("tags", []) or [])

    return {
        **tag_fields,
        "mitre_technique_names": [],
        "falsepositives": parsed.get("falsepositives", []) or [],
        "level": parsed.get("level"),
        "references": parsed.get("references", []) or [],
        "note": None,
        # Not in the tool's headline return-shape contract, but Sigma content
        # carries this and dropping fields we were explicitly asked to
        # extract (status/date/modified/logsource) rather than including
        # them somewhere is worse than an unlisted-but-present key.
        "status": parsed.get("status"),
        "date": parsed.get("date"),
        "modified": parsed.get("modified"),
        "logsource": parsed.get("logsource", {}) or {},
    }


def _parse_suricata(content: str) -> dict:
    title = ""
    m = MSG_RE.search(content)
    if m:
        title = m.group(1)

    # Collect ALL values per key, not just the last — a rule can legitimately
    # carry more than one mitre_technique_id/mitre_tactic_id pair. Phase B's
    # original parser used a flat dict here and silently kept only the last
    # value on a repeated key; fixed as part of this rewrite.
    metadata: dict[str, list[str]] = {}
    m = METADATA_RE.search(content)
    if m:
        for pair in m.group(1).split(","):
            pair = pair.strip()
            if not pair:
                continue
            parts = pair.split(None, 1)
            if len(parts) == 2:
                key, value = parts
                metadata.setdefault(key, []).append(value)

    # MISSING MITRE metadata is a valid, common, non-error case — absence
    # produces empty lists here, not an error or a gap marker.
    return {
        "title": title,
        "mitre_attack": metadata.get("mitre_technique_id", []),
        "mitre_tactics": metadata.get("mitre_tactic_id", []),
        "mitre_groups": [],
        "mitre_software": [],
        "mitre_technique_names": metadata.get("mitre_technique_name", []),
        "mitre_tactic_names": metadata.get("mitre_tactic_name", []),
        "falsepositives": [],
        "level": None,
        "references": [],
        "note": None,
    }


def _parse_yara() -> dict:
    """YARA has no native MITRE tagging convention — always an empty MITRE
    result, not an error. title/description/author come from so-detection's
    indexed fields directly (handled in the shared base dict), not re-parsed
    from content's meta: block."""
    return _empty_mitre_fields(note="YARA has no native MITRE tagging convention.")


if __name__ == "__main__":
    import json
    import sys

    uuid = sys.argv[1] if len(sys.argv) > 1 else ""
    engine = sys.argv[2] if len(sys.argv) > 2 else None
    if uuid:
        print(json.dumps(get_rule_source(uuid, engine), indent=2, default=str))
    else:
        print("Usage: python detection_rules.py <rule-uuid> [source_engine]")
