from __future__ import annotations

from langgraph.graph import END, StateGraph

from nodes.analyze import analyze
from nodes.correlate import correlate
from nodes.format_output import format_output
from nodes.investigate import investigate
from schemas import TriageState


def _route_after_correlate(state: TriageState) -> str:
    corr = state.get("correlation_result")
    if corr and corr.action == "deduplicated":
        return "format_output"
    return "investigate"


workflow = StateGraph(TriageState)

workflow.add_node("correlate", correlate)
workflow.add_node("investigate", investigate)
workflow.add_node("analyze", analyze)
workflow.add_node("format_output", format_output)

workflow.set_entry_point("correlate")

workflow.add_conditional_edges(
    "correlate",
    _route_after_correlate,
    {"investigate": "investigate", "format_output": "format_output"},
)

workflow.add_edge("investigate", "analyze")
workflow.add_edge("analyze", "format_output")
workflow.add_edge("format_output", END)

graph = workflow.compile()
