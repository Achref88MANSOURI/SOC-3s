from __future__ import annotations

from unittest.mock import patch

import requests

from tools.detection_rules import get_rule_source

# Real, high-volume, live-verified fixture (SOC-3s-ARCHITECTURE-v3-final.md,
# Elasticsearch so-detection rewrite): LSASS credential-access rule with all
# four attack.* tag namespaces present.
LSASS_SIGMA_CONTENT = """
title: Suspicious LSASS Process Access
id: ffa6861c-4461-4f59-8a41-578c39f3f23e
status: stable
description: Detects process access to LSASS which is typically done to dump credentials for lateral movement or privilege escalation
references:
    - https://example.com/lsass-dump
author: Florian Roth
date: 2020/01/01
modified: 2023/05/01
tags:
    - attack.credential-access
    - attack.t1003.001
    - attack.g0069
    - attack.s0002
    - detection.emerging-threats
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
    condition: selection
falsepositives:
    - Legitimate administration tasks
level: high
"""

NONSTANDARD_TACTIC_SIGMA_CONTENT = """
title: Suspicious Process Masquerading
id: 11111111-1111-1111-1111-111111111111
status: stable
description: Detects a process masquerading as a legitimate one
tags:
    - attack.stealth
    - attack.defense-impairment
logsource:
    category: process_creation
detection:
    condition: selection
"""

SURICATA_WITH_MITRE_CONTENT = (
    'alert tcp any any -> any any (msg:"ET ACTIVEX Something Bad"; '
    "flow:established; sid:2010665; rev:7; "
    "metadata:affected_product Windows, mitre_tactic_id TA0011, "
    "mitre_tactic_name Command_And_Control, mitre_technique_id T1071, "
    "mitre_technique_name Application_Layer_Protocol;)"
)

SURICATA_WITHOUT_MITRE_CONTENT = (
    'alert tcp any any -> $HOME_NET any (msg:"ET TOR Known Tor Relay/Router"; '
    "flow:established; sid:2522726; rev:6172; "
    "metadata:affected_product Any, attack_target Any, deployment Perimeter, "
    "tag TOR, signature_severity Informational;)"
)


def _es_response(so_detection: dict | None) -> dict:
    if so_detection is None:
        return {"hits": {"hits": []}}
    return {"hits": {"hits": [{"_source": {"so_detection": so_detection, "so_kind": "detection"}}]}}


def _sigma_doc(content: str, public_id: str) -> dict:
    return {
        "publicId": public_id,
        "content": content,
        "language": "sigma",
        "engine": "elastalert",
        "title": "Suspicious LSASS Process Access",
        "severity": "high",
        "description": "d",
        "author": "Florian Roth",
        "category": "process_access",
        "isEnabled": True,
        "isCommunity": True,
        "ruleset": "all_rules",
        "product": "windows",
    }


def _suricata_doc(content: str, public_id: str) -> dict:
    return {
        "publicId": public_id,
        "content": content,
        "language": "suricata",
        "engine": "suricata",
        "title": "ET rule",
        "severity": "unknown",
        "description": "",
        "author": "",
        "category": "ET MALWARE",
        "isEnabled": True,
        "isCommunity": True,
        "ruleset": "ETOPEN",
        "product": None,
    }


def _yara_doc(public_id: str) -> dict:
    return {
        "publicId": public_id,
        "content": "rule Powershell_Attack_Scripts { meta: author=\"x\" strings: $a = \"evil\" condition: $a }",
        "language": "yara",
        "engine": "strelka",
        "title": "Powershell Attack Scripts",
        "severity": "high",
        "description": "Detects malicious PowerShell scripts",
        "author": "SOC team",
        "category": "",
        "isEnabled": True,
        "isCommunity": True,
        "ruleset": "securityonion-yara",
        "product": None,
    }


@patch("tools.detection_rules._es_post")
def test_sigma_all_four_tag_namespaces_parsed(mock_post):
    mock_post.return_value = _es_response(_sigma_doc(LSASS_SIGMA_CONTENT, "ffa6861c-4461-4f59-8a41-578c39f3f23e"))

    result = get_rule_source("ffa6861c-4461-4f59-8a41-578c39f3f23e", "sigma")

    assert result["found"] is True
    assert result["source_engine"] == "sigma"
    assert result["mitre_attack"] == ["T1003.001"]
    assert result["mitre_tactics"] == ["credential-access"]
    assert result["mitre_groups"] == ["G0069"]
    assert result["mitre_software"] == ["S0002"]
    # detection.emerging-threats is not in the attack.* namespace — filtered out entirely
    assert "emerging-threats" not in result["mitre_tactics"]
    assert result["falsepositives"] == ["Legitimate administration tasks"]
    assert result["level"] == "high"


def test_sigma_subtechnique_normalized_to_uppercase():
    with patch("tools.detection_rules._es_post") as mock_post:
        mock_post.return_value = _es_response(_sigma_doc(LSASS_SIGMA_CONTENT, "ffa6861c-4461-4f59-8a41-578c39f3f23e"))
        result = get_rule_source("ffa6861c-4461-4f59-8a41-578c39f3f23e")
    assert "T1003.001" in result["mitre_attack"]


@patch("tools.detection_rules._es_post")
def test_sigma_nonstandard_tactic_name_accepted_not_rejected(mock_post):
    mock_post.return_value = _es_response(_sigma_doc(NONSTANDARD_TACTIC_SIGMA_CONTENT, "11111111-1111-1111-1111-111111111111"))

    result = get_rule_source("11111111-1111-1111-1111-111111111111")

    assert result["found"] is True
    assert "stealth" in result["mitre_tactics"]
    assert "defense-impairment" in result["mitre_tactics"]


@patch("tools.detection_rules._es_post")
def test_suricata_rule_with_mitre_metadata(mock_post):
    mock_post.return_value = _es_response(_suricata_doc(SURICATA_WITH_MITRE_CONTENT, "2010665"))

    result = get_rule_source("2010665", "suricata")

    assert result["found"] is True
    assert result["source_engine"] == "suricata"
    assert result["title"] == "ET ACTIVEX Something Bad"
    assert result["mitre_attack"] == ["T1071"]
    assert result["mitre_tactics"] == ["TA0011"]
    assert result["mitre_technique_names"] == ["Application_Layer_Protocol"]


@patch("tools.detection_rules._es_post")
def test_suricata_rule_without_mitre_metadata_is_not_an_error(mock_post):
    mock_post.return_value = _es_response(_suricata_doc(SURICATA_WITHOUT_MITRE_CONTENT, "2522726"))

    result = get_rule_source("2522726", "suricata")

    assert result["found"] is True
    assert result["title"] == "ET TOR Known Tor Relay/Router"
    assert result["mitre_attack"] == []
    assert result["mitre_tactics"] == []
    assert result.get("error") is None


@patch("tools.detection_rules._es_post")
def test_yara_rule_graceful_no_mitre(mock_post):
    mock_post.return_value = _es_response(_yara_doc("Powershell_Attack_Scripts"))

    result = get_rule_source("Powershell_Attack_Scripts", "yara")

    assert result["found"] is True
    assert result["source_engine"] == "yara"
    assert result["mitre_attack"] == []
    assert result["note"] is not None
    assert result["title"] == "Powershell Attack Scripts"
    assert result["description"] == "Detects malicious PowerShell scripts"
    assert result["author"] == "SOC team"


@patch("tools.detection_rules._es_post")
def test_unknown_public_id_not_found(mock_post):
    mock_post.return_value = _es_response(None)

    result = get_rule_source("no-such-rule")

    assert result["found"] is False
    assert result["public_id"] == "no-such-rule"


@patch("tools.detection_rules._es_post")
def test_es_request_error_returns_found_false_no_raise(mock_post):
    mock_post.side_effect = requests.exceptions.ConnectionError("timeout")

    result = get_rule_source("ffa6861c-4461-4f59-8a41-578c39f3f23e")

    assert result["found"] is False
    assert "timeout" in result["error"]


@patch("tools.detection_rules._es_post")
def test_source_engine_hint_disagreeing_with_index_language_language_wins(mock_post):
    # Caller (wrongly) hints "suricata" but the indexed document is Sigma —
    # so_detection.language must win, not the hint.
    mock_post.return_value = _es_response(_sigma_doc(LSASS_SIGMA_CONTENT, "ffa6861c-4461-4f59-8a41-578c39f3f23e"))

    result = get_rule_source("ffa6861c-4461-4f59-8a41-578c39f3f23e", source_engine="suricata")

    assert result["source_engine"] == "sigma"
    assert result["mitre_attack"] == ["T1003.001"]


@patch("tools.detection_rules._es_post")
def test_query_targets_so_detection_public_id(mock_post):
    mock_post.return_value = _es_response(None)

    get_rule_source("some-uuid")

    call_args = mock_post.call_args
    assert call_args.args[0] == "/so-detection/_search"
    assert call_args.args[1]["query"]["term"]["so_detection.publicId"] == "some-uuid"
