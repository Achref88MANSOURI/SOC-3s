from __future__ import annotations

from langgraph.graph import END, StateGraph

from nodes.analyze import analyze
from nodes.format_output import format_output
from nodes.investigate import investigate
from nodes.perceive import gate0_dedup, perceive
from schemas import TriageState


def _route_after_gate0(state: TriageState) -> str:
    corr = state.get("correlation_result")
    if corr and corr.action == "deduplicated":
        return "format_output"
    return "perceive"


def _route_after_perceive(state: TriageState) -> str:
    corr = state.get("correlation_result")
    if corr and corr.action == "deduplicated":
        return "format_output"
    return "investigate"


workflow = StateGraph(TriageState)

workflow.add_node("gate0", gate0_dedup)
workflow.add_node("perceive", perceive)
workflow.add_node("investigate", investigate)
workflow.add_node("analyze", analyze)
workflow.add_node("format_output", format_output)

workflow.set_entry_point("gate0")

workflow.add_conditional_edges(
    "gate0",
    _route_after_gate0,
    {"perceive": "perceive", "format_output": "format_output"},
)
workflow.add_conditional_edges(
    "perceive",
    _route_after_perceive,
    {"investigate": "investigate", "format_output": "format_output"},
)

workflow.add_edge("investigate", "analyze")
workflow.add_edge("analyze", "format_output")
workflow.add_edge("format_output", END)

graph = workflow.compile()
