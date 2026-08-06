from __future__ import annotations

from schemas import CorrelationResult, TriageState


def test_route_after_gate0_dedup():
    from graph import _route_after_gate0
    state: TriageState = {
        "correlation_result": CorrelationResult(action="deduplicated", mode="new"),
    }
    assert _route_after_gate0(state) == "format_output"


def test_route_after_gate0_no_dedup():
    from graph import _route_after_gate0
    state: TriageState = {"correlation_result": None}
    assert _route_after_gate0(state) == "perceive"


def test_route_after_gate0_no_result():
    from graph import _route_after_gate0
    state: TriageState = {}
    assert _route_after_gate0(state) == "perceive"


def test_route_after_perceive_dedup():
    from graph import _route_after_perceive
    state: TriageState = {
        "correlation_result": CorrelationResult(action="deduplicated", mode="new"),
    }
    assert _route_after_perceive(state) == "format_output"


def test_route_after_perceive_new():
    from graph import _route_after_perceive
    state: TriageState = {
        "correlation_result": CorrelationResult(action="new", mode="new"),
    }
    assert _route_after_perceive(state) == "investigate"


def test_route_after_perceive_merge():
    from graph import _route_after_perceive
    state: TriageState = {
        "correlation_result": CorrelationResult(
            action="merge", mode="merge", merge_into_case="case-001",
        ),
    }
    assert _route_after_perceive(state) == "investigate"


def test_route_after_perceive_no_result():
    from graph import _route_after_perceive
    state: TriageState = {}
    assert _route_after_perceive(state) == "investigate"


def test_graph_nodes():
    from graph import workflow
    assert "gate0" in workflow.nodes
    assert "perceive" in workflow.nodes
    assert "investigate" in workflow.nodes
    assert "analyze" in workflow.nodes
    assert "format_output" in workflow.nodes
