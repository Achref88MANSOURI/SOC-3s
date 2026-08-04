from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from config import SIGMA_RULES_PATH, SURICATA_RULES_PATH

# Suricata: matches the sid on its own line-scoped boundary. sid is Emerging
# Threats' own sequential rule identifier, NOT a MITRE technique ID — it is
# used purely as the lookup key into the rules file. The real MITRE data, when
# present, lives in that same rule's `metadata:` block as separate key-value
# pairs. See SOC-3s-ARCHITECTURE-v3-final.md §7 for the confirmed rule format
# and the "critical correction" this reflects.
MSG_RE = re.compile(r'msg:"([^"]*)"')
METADATA_RE = re.compile(r"metadata:([^;]*);")

_MITRE_METADATA_KEYS = ("mitre_technique_id", "mitre_technique_name", "mitre_tactic_id", "mitre_tactic_name")


def get_rule_source(rule_uuid: str, source_engine: str | None = None) -> dict:
    """Look up a detection rule's source and MITRE metadata by UUID, across all
    three Security Onion detection engines. If source_engine is given, dispatch
    straight to that engine's lookup. Otherwise try each in turn: Sigma YAML ->
    Suricata .rules metadata -> YARA graceful return (per
    SOC-3s-ARCHITECTURE-v3-final.md §11's confirmed dispatch order)."""
    engine = (source_engine or "").lower()

    if engine == "sigma":
        return _get_sigma_rule_source(rule_uuid)
    if engine == "suricata":
        return _get_suricata_rule_source(rule_uuid)
    if engine in ("yara", "strelka"):
        return _get_yara_rule_source(rule_uuid)

    result = _get_sigma_rule_source(rule_uuid)
    if result.get("found"):
        return result
    result = _get_suricata_rule_source(rule_uuid)
    if result.get("found"):
        return result
    return _get_yara_rule_source(rule_uuid)


def _get_sigma_rule_source(rule_uuid: str) -> dict:
    rules_dir = Path(SIGMA_RULES_PATH)
    if not rules_dir.is_dir():
        return {
            "found": False,
            "source_engine": "sigma",
            "error": f"Sigma rules directory not found: {SIGMA_RULES_PATH}",
            "rule_uuid": rule_uuid,
        }

    for root, _dirs, files in os.walk(rules_dir):
        for fname in files:
            if not fname.endswith((".yml", ".yaml")):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r") as f:
                    data = yaml.safe_load(f)
                if not isinstance(data, dict):
                    continue
                if data.get("id", "").strip() == rule_uuid.strip():
                    return _extract_sigma_rule(data)
            except (yaml.YAMLError, OSError):
                continue

    return {
        "found": False,
        "source_engine": "sigma",
        "error": f"No Sigma rule found with UUID '{rule_uuid}'",
        "rule_uuid": rule_uuid,
    }


def _extract_sigma_rule(data: dict) -> dict:
    tags = data.get("tags", []) or []
    return {
        "found": True,
        "source_engine": "sigma",
        "title": data.get("title", ""),
        "description": data.get("description", ""),
        "id": data.get("id", ""),
        "level": data.get("level", ""),
        "status": data.get("status", ""),
        "falsepositives": data.get("falsepositives", []),
        "tags": tags,
        "mitre_attack": [t for t in tags if t.startswith("attack.")],
        "references": data.get("references", []),
        "author": data.get("author", ""),
        "detection": data.get("detection", {}),
        "logsource": data.get("logsource", {}),
    }


def _get_suricata_rule_source(rule_uuid: str) -> dict:
    rules_path = Path(SURICATA_RULES_PATH)
    if not rules_path.is_file():
        return {
            "found": False,
            "source_engine": "suricata",
            "error": f"Suricata rules file not found: {SURICATA_RULES_PATH}",
            "rule_uuid": rule_uuid,
        }

    sid_marker = f"sid:{rule_uuid};"
    try:
        with open(rules_path, "r", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if sid_marker in stripped:
                    return _extract_suricata_rule(stripped, rule_uuid)
    except OSError as e:
        return {
            "found": False,
            "source_engine": "suricata",
            "error": str(e),
            "rule_uuid": rule_uuid,
        }

    return {
        "found": False,
        "source_engine": "suricata",
        "error": f"No Suricata rule found with SID '{rule_uuid}'",
        "rule_uuid": rule_uuid,
    }


def _extract_suricata_rule(line: str, rule_uuid: str) -> dict:
    title = ""
    m = MSG_RE.search(line)
    if m:
        title = m.group(1)

    metadata: dict[str, str] = {}
    m = METADATA_RE.search(line)
    if m:
        for pair in m.group(1).split(","):
            pair = pair.strip()
            if not pair:
                continue
            parts = pair.split(None, 1)
            if len(parts) == 2:
                metadata[parts[0]] = parts[1]
            # A metadata key with no value (malformed/unexpected) is skipped
            # rather than guessed — matches the rest of this module's "no
            # structured field is invented" discipline.

    # MISSING MITRE metadata is a valid, common, non-error case (confirmed:
    # only 50.2% of active rules in this deployment have mitre_technique_id at
    # all) — absence produces empty lists here, not an error or a gap marker.
    mitre_attack = [metadata["mitre_technique_id"]] if metadata.get("mitre_technique_id") else []
    mitre_tactics = [metadata["mitre_tactic_id"]] if metadata.get("mitre_tactic_id") else []

    return {
        "found": True,
        "source_engine": "suricata",
        "title": title,
        "rule_uuid": rule_uuid,
        "mitre_attack": mitre_attack,
        "mitre_tactics": mitre_tactics,
        "mitre_technique_name": metadata.get("mitre_technique_name", ""),
        "mitre_tactic_name": metadata.get("mitre_tactic_name", ""),
        "metadata": metadata,
    }


def _get_yara_rule_source(rule_uuid: str) -> dict:
    """YARA/Strelka rules have no centrally indexed, filesystem-lookup-by-UUID
    mechanism the way Sigma (YAML directory) and Suricata (single .rules file
    with a sid key) do, and no native MITRE tagging convention — confirmed via
    Security Onion's own strelka.file ingest pipeline (arbitrary YARA rule meta
    keys flatten to rule.{key}, so MITRE tagging is possible per-rule but never
    structurally guaranteed). This is a graceful, always-empty return, not an
    error — the caller should not treat this as a failed lookup."""
    return {
        "found": False,
        "source_engine": "yara",
        "error": "YARA/Strelka rules have no centrally indexed lookup by UUID; no native MITRE tagging mechanism exists for this engine",
        "rule_uuid": rule_uuid,
        "mitre_attack": [],
        "mitre_tactics": [],
    }


if __name__ == "__main__":
    import json
    import sys

    uuid = sys.argv[1] if len(sys.argv) > 1 else ""
    engine = sys.argv[2] if len(sys.argv) > 2 else None
    if uuid:
        print(json.dumps(get_rule_source(uuid, engine), indent=2, default=str))
    else:
        print("Usage: python detection_rules.py <rule-uuid> [source_engine]")
