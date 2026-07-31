from __future__ import annotations

import os
from pathlib import Path

import yaml

from config import SIGMA_RULES_PATH


def get_rule_source(rule_uuid: str) -> dict | None:
    rules_dir = Path(SIGMA_RULES_PATH)
    if not rules_dir.is_dir():
        return {"found": False, "error": f"Sigma rules directory not found: {SIGMA_RULES_PATH}", "rule_uuid": rule_uuid}

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
                    return _extract(data)
            except (yaml.YAMLError, OSError):
                continue

    return {"found": False, "error": f"No Sigma rule found with UUID '{rule_uuid}'", "rule_uuid": rule_uuid}


def _extract(data: dict) -> dict:
    tags = data.get("tags", []) or []
    return {
        "found": True,
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


if __name__ == "__main__":
    import sys
    uuid = sys.argv[1] if len(sys.argv) > 1 else ""
    if uuid:
        import json
        print(json.dumps(get_rule_source(uuid), indent=2, default=str))
    else:
        print("Usage: python sigma_rules.py <rule-uuid>")
