from __future__ import annotations

from schemas import CorrelationResult, TriageState


def test_route_after_correlate_dedup():
    from graph import _route_after_correlate
    state: TriageState = {
        "correlation_result": CorrelationResult(action="deduplicated", mode="new"),
    }
    assert _route_after_correlate(state) == "format_output"


def test_route_after_correlate_new():
    from graph import _route_after_correlate
    state: TriageState = {
        "correlation_result": CorrelationResult(action="new", mode="new"),
    }
    assert _route_after_correlate(state) == "investigate"


def test_route_after_correlate_merge():
    from graph import _route_after_correlate
    state: TriageState = {
        "correlation_result": CorrelationResult(
            action="merge", mode="merge", merge_into_case="case-001",
        ),
    }
    assert _route_after_correlate(state) == "investigate"


def test_route_after_correlate_no_result():
    from graph import _route_after_correlate
    state: TriageState = {}
    assert _route_after_correlate(state) == "investigate"


def test_graph_nodes():
    from graph import workflow
    assert "correlate" in workflow.nodes
    assert "investigate" in workflow.nodes
    assert "analyze" in workflow.nodes
    assert "format_output" in workflow.nodes
