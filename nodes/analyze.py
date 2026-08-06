from __future__ import annotations

import json
import logging

from langchain_openai import ChatOpenAI

from config import settings
from prompts.analyst import build_prompt, output_schema
from schemas import DeltaVerdict, TriageState, TriageVerdict

logger = logging.getLogger("agent-service.analyze")

_llm = ChatOpenAI(
    base_url=settings.llm_base_url,
    api_key=settings.llm_api_key or "sk-no-auth",
    model=settings.llm_model,
    temperature=0.0,
    max_tokens=1024,
)


def _truncate(obj, max_len: int = 500) -> str:
    s = json.dumps(obj, default=str)
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s


def _summarize_evidence(ep) -> dict:
    d = ep.model_dump() if hasattr(ep, "model_dump") else (ep if isinstance(ep, dict) else {})

    summary = {
        "rule_context": d.get("rule_context", {}),
        "asset_context": d.get("asset_context", {}),
        "threat_intel_summary": [],
        "temporal_context": {
            "total_related_alerts": len(d.get("temporal_context", {}).get("related_alerts_24h", [])),
            "host": d.get("temporal_context", {}).get("host"),
            "user": d.get("temporal_context", {}).get("user"),
        },
        "historical_context": {
            "total_past_cases": len(d.get("historical_context", {}).get("similar_past_cases", [])),
        },
        "investigation_gaps": d.get("investigation_gaps", []),
    }

    for ti in d.get("threat_intel", []):
        summary["threat_intel_summary"].append({
            "observable": ti.get("observable"),
            "type": ti.get("type"),
            "verdict": ti.get("verdict"),
            "score": ti.get("score"),
            "details": ti.get("details", "")[:300],
            "analyzer": ti.get("analyzer"),
        })

    return summary


def _extract_json(text: str) -> str | None:
    text = text.strip()
    if not text:
        return None
    if text.startswith("```"):
        lines = text.split("\n")
        cleaned = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(cleaned).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start:end + 1]
    return None


def analyze(state: TriageState) -> TriageState:
    mode = state.get("mode", "new")
    system_prompt = build_prompt(mode)
    schema = output_schema(mode)

    if mode == "new":
        evidence = state.get("evidence_package")
        evidence_summary = _summarize_evidence(evidence)
        agent1_mitre_mapping = state.get("mitre_mapping") or []
        agent1_mapping_dump = [
            m.model_dump() if hasattr(m, "model_dump") else m for m in agent1_mitre_mapping
        ]
        human_content = (
            f"agent1_initial_mitre_mapping (fast, approximate — made from alert context "
            f"alone before evidence was gathered; validate and refine against the "
            f"evidence below, do not copy blindly):\n{json.dumps(agent1_mapping_dump, indent=2, default=str)}\n\n"
            f"evidence_package_summary:\n{json.dumps(evidence_summary, indent=2)}\n\n"
            f"Respond with ONLY valid JSON matching this schema:\n{json.dumps(schema)}"
        )
    else:
        ctx = state.get("existing_case_context") or {}
        delta = state.get("delta_evidence")
        human_content = (
            f"existing_case_context:\n{json.dumps(ctx, default=str)}\n\n"
            f"delta_evidence:\n{json.dumps(_summarize_evidence(delta), indent=2)}\n\n"
            f"Respond with ONLY valid JSON matching this schema:\n{json.dumps(schema)}"
        )

    response = _llm.invoke([
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": human_content},
    ])

    raw = response.content if isinstance(response.content, str) else json.dumps(response.content)
    logger.info("Analyze LLM response (first 300 chars): %s", raw[:300])

    extracted = _extract_json(raw)
    parsed = None
    if extracted:
        try:
            parsed = json.loads(extracted)
        except json.JSONDecodeError:
            parsed = None

    if mode == "new":
        if parsed is None:
            state["triage_verdict"] = TriageVerdict(
                likelihood="possible",
                impact_if_true="moderate",
                verdict="needs_review",
                reasoning="Analyst output failed to parse — flagged for manual review.",
                recommended_action="needs_review",
                summary="Automated analysis could not be completed; manual review required.",
            )
        else:
            state["triage_verdict"] = TriageVerdict(**parsed)
        state["delta_verdict"] = None
    else:
        if parsed is None:
            state["delta_verdict"] = DeltaVerdict(
                urgency="routine_merge",
                recommended_action="merge_quiet",
                reasoning="Analyst output failed to parse — merged quietly pending manual review.",
            )
        else:
            state["delta_verdict"] = DeltaVerdict(**parsed)
        state["triage_verdict"] = None

    return state
