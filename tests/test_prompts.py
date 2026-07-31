from __future__ import annotations

from prompts.investigator import build_prompt as build_investigator_prompt, PROFILE_BLOCKS
from prompts.analyst import build_prompt as build_analyst_prompt, output_schema


def test_investigator_build_prompt_new():
    prompt = build_investigator_prompt("network_threat", "new")
    assert "network_threat" in prompt
    assert "NEW alert" in prompt
    assert "sigma_rule_lookup" in prompt


def test_investigator_build_prompt_merge():
    prompt = build_investigator_prompt("endpoint_behavior", "merge")
    assert "MODE: MERGE" in prompt
    assert "endpoint_behavior" in prompt
    assert "existing open case" in prompt


def test_investigator_build_prompt_generic():
    prompt = build_investigator_prompt("unknown_profile", "new")
    assert "generic" in prompt


def test_investigator_all_profiles():
    for profile in ("network_threat", "endpoint_behavior", "malicious_file", "network_anomaly", "log_anomaly"):
        prompt = build_investigator_prompt(profile, "new")
        assert profile in prompt


def test_analyst_build_prompt_new():
    prompt = build_analyst_prompt("new")
    assert "likelihood" in prompt
    assert "impact_if_true" in prompt
    assert "verdict" in prompt
    assert "MERGE" not in prompt


def test_analyst_build_prompt_merge():
    prompt = build_analyst_prompt("merge")
    assert "MERGE" in prompt


def test_output_schema_new():
    schema = output_schema("new")
    assert "likelihood" in schema["properties"]
    assert "impact_if_true" in schema["properties"]
    assert "verdict" in schema["properties"]
    assert "reasoning" in schema["required"]


def test_output_schema_merge():
    schema = output_schema("merge")
    assert "severity_change" in schema["properties"]
    assert "urgency" in schema["properties"]
    assert "recommended_action" in schema["properties"]
    assert "new_mitre_stages" in schema["properties"]


def test_profile_blocks_have_all_fields():
    for profile, block in PROFILE_BLOCKS.items():
        assert "## Investigation profile:" in block
        assert profile in block
