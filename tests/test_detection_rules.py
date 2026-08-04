from __future__ import annotations

from unittest.mock import patch

from tools.detection_rules import get_rule_source

# Rule text below matches the confirmed real format from
# SOC-3s-ARCHITECTURE-v3-final.md §7, pulled directly from the live deployment.
SURICATA_RULE_WITH_MITRE = (
    'alert tcp any any -> any any (msg:"ET ACTIVEX Something Bad"; '
    "flow:established; sid:2010665; rev:7; "
    "metadata:affected_product Windows, mitre_tactic_id TA0001, "
    "mitre_tactic_name Initial_Access, mitre_technique_id T1190, "
    "mitre_technique_name Exploit_Public_Facing_Application;)\n"
)

SURICATA_RULE_WITHOUT_MITRE = (
    'alert tcp any any -> $HOME_NET any (msg:"ET TOR Known Tor Relay/Router"; '
    "flow:established; sid:2522726; rev:6172; "
    "metadata:affected_product Any, attack_target Any, deployment Perimeter, "
    "tag TOR, signature_severity Informational, created_at 2008_12_01, "
    "updated_at 2026_02_19;)\n"
)

SURICATA_RULE_COMMENTED = (
    '# alert tcp any any -> any any (msg:"Disabled rule"; sid:9999999; rev:1;)\n'
)


def _write_suricata_rules(tmp_path, *lines) -> str:
    path = tmp_path / "all.rules"
    path.write_text("".join(lines))
    return str(path)


def test_suricata_rule_with_mitre_metadata(tmp_path):
    rules_path = _write_suricata_rules(tmp_path, SURICATA_RULE_WITH_MITRE)
    with patch("tools.detection_rules.SURICATA_RULES_PATH", rules_path):
        result = get_rule_source("2010665", "suricata")

    assert result["found"] is True
    assert result["source_engine"] == "suricata"
    assert result["title"] == "ET ACTIVEX Something Bad"
    assert result["mitre_attack"] == ["T1190"]
    assert result["mitre_tactics"] == ["TA0001"]
    assert result["mitre_technique_name"] == "Exploit_Public_Facing_Application"
    assert result["mitre_tactic_name"] == "Initial_Access"


def test_suricata_rule_without_mitre_metadata_is_not_an_error(tmp_path):
    rules_path = _write_suricata_rules(tmp_path, SURICATA_RULE_WITHOUT_MITRE)
    with patch("tools.detection_rules.SURICATA_RULES_PATH", rules_path):
        result = get_rule_source("2522726", "suricata")

    assert result["found"] is True
    assert result["title"] == "ET TOR Known Tor Relay/Router"
    assert result["mitre_attack"] == []
    assert result["mitre_tactics"] == []
    assert "error" not in result


def test_suricata_commented_rule_is_skipped(tmp_path):
    rules_path = _write_suricata_rules(tmp_path, SURICATA_RULE_COMMENTED)
    with patch("tools.detection_rules.SURICATA_RULES_PATH", rules_path):
        result = get_rule_source("9999999", "suricata")

    assert result["found"] is False


def test_suricata_unknown_sid(tmp_path):
    rules_path = _write_suricata_rules(tmp_path, SURICATA_RULE_WITH_MITRE)
    with patch("tools.detection_rules.SURICATA_RULES_PATH", rules_path):
        result = get_rule_source("404404", "suricata")

    assert result["found"] is False
    assert result["source_engine"] == "suricata"
    assert "404404" in result["error"]


def test_suricata_sid_substring_does_not_false_positive(tmp_path):
    """sid:2010665; must not match a lookup for '10665' or '665' — the ';'
    boundary after the digits prevents partial-number matches."""
    rules_path = _write_suricata_rules(tmp_path, SURICATA_RULE_WITH_MITRE)
    with patch("tools.detection_rules.SURICATA_RULES_PATH", rules_path):
        assert get_rule_source("10665", "suricata")["found"] is False
        assert get_rule_source("665", "suricata")["found"] is False


def test_suricata_rules_file_missing(tmp_path):
    missing_path = str(tmp_path / "does-not-exist.rules")
    with patch("tools.detection_rules.SURICATA_RULES_PATH", missing_path):
        result = get_rule_source("2010665", "suricata")

    assert result["found"] is False
    assert result["source_engine"] == "suricata"
    assert "not found" in result["error"]


def test_yara_graceful_return():
    result = get_rule_source("Malicious_PE_Generic", "yara")

    assert result["found"] is False
    assert result["source_engine"] == "yara"
    assert result["mitre_attack"] == []
    assert result["mitre_tactics"] == []
    assert "error" in result  # explains why, but isn't an exception


def test_strelka_alias_routes_to_yara_graceful_return():
    result = get_rule_source("Malicious_PE_Generic", "strelka")
    assert result["source_engine"] == "yara"
    assert result["found"] is False


def test_dispatch_with_no_engine_hint_tries_sigma_then_suricata_then_yara(tmp_path):
    """No source_engine given: Sigma lookup will miss (no rules dir configured
    to match), Suricata should be tried next and found."""
    rules_path = _write_suricata_rules(tmp_path, SURICATA_RULE_WITH_MITRE)
    missing_sigma_dir = str(tmp_path / "no-such-sigma-dir")
    with patch("tools.detection_rules.SIGMA_RULES_PATH", missing_sigma_dir), \
         patch("tools.detection_rules.SURICATA_RULES_PATH", rules_path):
        result = get_rule_source("2010665")

    assert result["found"] is True
    assert result["source_engine"] == "suricata"


def test_dispatch_with_no_engine_hint_falls_back_to_yara_graceful_return(tmp_path):
    missing_sigma_dir = str(tmp_path / "no-such-sigma-dir")
    missing_suricata_file = str(tmp_path / "no-such.rules")
    with patch("tools.detection_rules.SIGMA_RULES_PATH", missing_sigma_dir), \
         patch("tools.detection_rules.SURICATA_RULES_PATH", missing_suricata_file):
        result = get_rule_source("unknown-uuid")

    assert result["found"] is False
    assert result["source_engine"] == "yara"


def test_sigma_rule_found(tmp_path):
    rule_yaml = """
title: Suspicious PowerShell Download
id: 5e3cc4d8-3e68-43db-8656-eaaeefdec9cc
status: stable
description: Detects suspicious PowerShell download activity
level: high
tags:
    - attack.execution
    - attack.t1059.001
falsepositives:
    - Unknown
logsource:
    category: process_creation
detection:
    condition: selection
"""
    (tmp_path / "rule.yml").write_text(rule_yaml)
    with patch("tools.detection_rules.SIGMA_RULES_PATH", str(tmp_path)):
        result = get_rule_source("5e3cc4d8-3e68-43db-8656-eaaeefdec9cc", "sigma")

    assert result["found"] is True
    assert result["source_engine"] == "sigma"
    assert result["title"] == "Suspicious PowerShell Download"
    assert "attack.t1059.001" in result["mitre_attack"]


def test_sigma_rule_not_found(tmp_path):
    with patch("tools.detection_rules.SIGMA_RULES_PATH", str(tmp_path)):
        result = get_rule_source("no-such-uuid", "sigma")

    assert result["found"] is False
    assert result["source_engine"] == "sigma"
