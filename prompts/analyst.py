from __future__ import annotations

BASE_PROMPT = """You must respond with ONLY valid JSON. No markdown, no backticks, no explanations before or after. The JSON will be parsed programmatically.

You are a senior SOC analyst. Your job is to receive structured evidence and make the call.

## Core constraints
- You have NO tools. You analyze evidence only.
- You NEVER see raw logs or raw API responses.
- Never invent evidence. Never fill gaps with assumptions.
- Every claim in your reasoning MUST cite a specific field from the evidence provided.

## Reasoning process
Step 1 — Assess likelihood (grounded in evidence):
  Options: unlikely | possible | likely | near_certain
  Basis: TI verdicts, rule FP match, behavioral context, temporal clustering, historical cases.

Step 2 — Assess impact_if_true (grounded in asset + technique):
  Options: minor | moderate | severe | critical
  Basis: asset criticality, technique severity, scope of affected systems, data sensitivity.

Step 3 — MITRE mapping:
  Produce an array of {tactic, technique, sub_technique|null, confidence, basis}.
  Confidence is capped by evidence quality.
  sub_technique only when evidence specifically supports it.

Step 4 — Verdict:
  Options: true_positive | false_positive | needs_review

Step 5 — Reasoning:
  Every claim cites a specific field. E.g. "asset_context.criticality=high drove impact assessment"

Step 6 — Recommended action:
  Options: create_case | close_fp | needs_review

Step 7 — Summary:
  3-5 sentences, analyst-readable, no jargon inflation.

## Quality bar
- A verdict is only as good as the evidence it cites.
- If evidence has gaps, confidence must reflect that.
- "I don't know" expressed as needs_review is CORRECT.
- Overconfident verdicts on incomplete evidence are the FAILURE MODE.
"""

MERGE_PROMPT = """
## Mode: MERGE — delta assessment
You are assessing whether a new alert materially changes an existing open case.

Answer ONE question: does this new evidence change the case?

Output fields:
- severity_change: "medium -> high" | "no_change"
- new_mitre_stages: [] | [{"tactic": "...", "technique": "..."}]
- scope_change: "1 host -> 3 hosts" | "no_change"
- urgency: escalate | routine_merge
- recommended_action: merge_and_retier | merge_quiet
- reasoning: cite delta_evidence fields specifically
"""

NEW_SCHEMA = {
    "type": "object",
    "properties": {
        "likelihood": {"type": "string", "enum": ["unlikely", "possible", "likely", "near_certain"]},
        "impact_if_true": {"type": "string", "enum": ["minor", "moderate", "severe", "critical"]},
        "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "needs_review"]},
        "mitre_mapping": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "tactic": {"type": "string"},
                    "technique": {"type": "string"},
                    "sub_technique": {"type": ["string", "null"]},
                    "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                    "basis": {"type": "string"},
                },
                "required": ["tactic", "technique", "confidence", "basis"],
            },
        },
        "reasoning": {"type": "string"},
        "recommended_action": {"type": "string", "enum": ["create_case", "close_fp", "needs_review"]},
        "summary": {"type": "string"},
    },
    "required": ["likelihood", "impact_if_true", "verdict", "reasoning", "recommended_action", "summary"],
}

MERGE_SCHEMA = {
    "type": "object",
    "properties": {
        "severity_change": {"type": "string"},
        "new_mitre_stages": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "tactic": {"type": "string"},
                    "technique": {"type": "string"},
                },
            },
        },
        "scope_change": {"type": "string"},
        "urgency": {"type": "string", "enum": ["escalate", "routine_merge"]},
        "recommended_action": {"type": "string", "enum": ["merge_and_retier", "merge_quiet"]},
        "reasoning": {"type": "string"},
    },
    "required": ["severity_change", "scope_change", "urgency", "recommended_action", "reasoning"],
}

# GBNF grammar for LLM inference server (llama.cpp compatible)
GBNF_GRAMMAR = r"""
root ::= new-output | merge-output

new-output ::= "{" ws
  "\"likelihood\""  ws ":" ws likelihood ws "," ws
  "\"impact_if_true\"" ws ":" ws impact ws "," ws
  "\"verdict\"" ws ":" ws verdict ws "," ws
  "\"mitre_mapping\"" ws ":" ws "[" ws mitre-items? ws "]" ws "," ws
  "\"reasoning\"" ws ":" ws string ws "," ws
  "\"recommended_action\"" ws ":" ws action ws "," ws
  "\"summary\"" ws ":" ws string ws "}"

merge-output ::= "{" ws
  "\"severity_change\"" ws ":" ws string ws "," ws
  "\"new_mitre_stages\"" ws ":" ws "[" ws "]" ws "," ws
  "\"scope_change\"" ws ":" ws string ws "," ws
  "\"urgency\"" ws ":" ws urgency ws "," ws
  "\"recommended_action\"" ws ":" ws merge-action ws "," ws
  "\"reasoning\"" ws ":" ws string ws "}"

likelihood ::= "\"unlikely\"" | "\"possible\"" | "\"likely\"" | "\"near_certain\""
impact ::= "\"minor\"" | "\"moderate\"" | "\"severe\"" | "\"critical\""
verdict ::= "\"true_positive\"" | "\"false_positive\"" | "\"needs_review\""
action ::= "\"create_case\"" | "\"close_fp\"" | "\"needs_review\""
urgency ::= "\"escalate\"" | "\"routine_merge\""
merge-action ::= "\"merge_and_retier\"" | "\"merge_quiet\""

mitre-items ::= mitre-item ("," ws mitre-item)*
mitre-item ::= "{" ws
  "\"tactic\"" ws ":" ws string ws "," ws
  "\"technique\"" ws ":" ws string ws "," ws
  "\"sub_technique\"" ws ":" ws (string | "null") ws "," ws
  "\"confidence\"" ws ":" ws confidence ws "," ws
  "\"basis\"" ws ":" ws string ws "}"
confidence ::= "\"low\"" | "\"medium\"" | "\"high\""
string ::= "\"" [^\"]* "\""
ws ::= [ \t\n]*
"""


def build_prompt(mode: str) -> str:
    return BASE_PROMPT + (MERGE_PROMPT if mode == "merge" else "")


def output_schema(mode: str) -> dict:
    return MERGE_SCHEMA if mode == "merge" else NEW_SCHEMA


def grammar(mode: str) -> str | None:
    return GBNF_GRAMMAR
