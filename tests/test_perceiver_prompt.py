from __future__ import annotations

from prompts.perceiver import build_prompt


def test_all_six_perception_tools_documented():
    prompt = build_prompt()
    for tool_name in (
        "get_fp_signal",
        "thehive_fp_history",
        "detection_rule_lookup",
        "qdrant_retrieve_mitre",
        "thehive_open_cases",
        "get_case_full",
    ):
        assert tool_name in prompt


def test_get_fp_signal_documented_as_called_first():
    prompt = build_prompt()
    tool_order_section = prompt.split("## Tool call order")[1].split("##")[0]
    assert tool_order_section.strip().startswith("1. get_fp_signal")


def test_fp_history_conditional_threshold_documented():
    prompt = build_prompt()
    assert "0.5" in prompt
    assert ">= 5" in prompt or ">=5" in prompt


def test_fp_guardrail_present():
    prompt = build_prompt()
    assert "never auto-decides" in prompt or "never" in prompt.lower() and "auto-decide" in prompt.lower()


def test_suricata_sid_is_lookup_key_not_mitre_id_documented():
    prompt = build_prompt()
    assert "SID" in prompt
    assert "NEVER a" in prompt or "never a" in prompt.lower()


def test_get_case_full_documented_after_open_cases():
    prompt = build_prompt()
    open_cases_idx = prompt.index("5. thehive_open_cases")
    case_full_idx = prompt.index("6. get_case_full")
    assert case_full_idx > open_cases_idx


def test_no_kibana_reference():
    prompt = build_prompt()
    assert "kibana" not in prompt.lower()
