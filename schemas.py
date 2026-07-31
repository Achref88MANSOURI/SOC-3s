from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict

from pydantic import BaseModel, Field


class HashBundle(BaseModel):
    md5: list[str] = Field(default_factory=list)
    sha1: list[str] = Field(default_factory=list)
    sha256: list[str] = Field(default_factory=list)
    sha512: list[str] = Field(default_factory=list)


class Observables(BaseModel):
    external_ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    hashes: HashBundle = Field(default_factory=HashBundle)


class Rule(BaseModel):
    name: str
    uuid: str
    native_severity: int
    category: Optional[str] = None
    product: Optional[str] = None


class Host(BaseModel):
    hostname: Optional[str] = None
    ip: list[str] = Field(default_factory=list)
    os: dict[str, Any] = Field(default_factory=dict)


class User(BaseModel):
    name: Optional[str] = None
    id: Optional[str] = None


class Network(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_total: Optional[int] = None
    packets_total: Optional[int] = None


class Process(BaseModel):
    pid: Optional[int] = None
    name: Optional[str] = None
    path: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None


class File(BaseModel):
    name: Optional[str] = None
    path: Optional[str] = None
    size: Optional[int] = None
    mime_type: Optional[str] = None


class CanonicalAlert(BaseModel):
    alert_id: str
    timestamp: datetime
    source_engine: str
    investigation_profile: str
    rule: Rule
    host: Optional[Host] = None
    user: Optional[User] = None
    network: Optional[Network] = None
    process: Optional[Process] = None
    file: Optional[File] = None
    observables: Observables = Field(default_factory=Observables)
    thehive_alert_id: str = ""
    thehive_observable_ids: dict[str, Any] = Field(default_factory=dict)


class CortexResult(BaseModel):
    observable: str
    type: str
    verdict: str
    score: int
    details: str
    analyzer: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class InvestigationTraceEntry(BaseModel):
    tool: str
    params: dict[str, Any] = Field(default_factory=dict)
    result_summary: str = ""


class EvidencePackage(BaseModel):
    rule_context: dict[str, Any] = Field(default_factory=dict)
    asset_context: dict[str, Any] = Field(default_factory=dict)
    threat_intel: list[CortexResult] = Field(default_factory=list)
    temporal_context: dict[str, Any] = Field(default_factory=dict)
    historical_context: dict[str, Any] = Field(default_factory=dict)
    investigation_gaps: list[str] = Field(default_factory=list)
    investigation_trace: list[InvestigationTraceEntry] = Field(default_factory=list)


class DeltaEvidence(BaseModel):
    new_iocs: list[str] = Field(default_factory=list)
    new_hosts: list[str] = Field(default_factory=list)
    new_users: list[str] = Field(default_factory=list)
    new_kill_chain_stages: list[str] = Field(default_factory=list)
    changed_ti_verdicts: list[dict[str, Any]] = Field(default_factory=list)
    additional_context: dict[str, Any] = Field(default_factory=dict)
    investigation_gaps: list[str] = Field(default_factory=list)
    investigation_trace: list[InvestigationTraceEntry] = Field(default_factory=list)


class MitreMapping(BaseModel):
    tactic: str
    technique: str
    sub_technique: Optional[str] = None
    confidence: str = "low"
    basis: str = ""


class TriageVerdict(BaseModel):
    likelihood: str
    impact_if_true: str
    verdict: str
    mitre_mapping: list[MitreMapping] = Field(default_factory=list)
    reasoning: str = ""
    recommended_action: str = "needs_review"
    summary: str = ""


class DeltaVerdict(BaseModel):
    severity_change: str = "no_change"
    new_mitre_stages: list[dict[str, str]] = Field(default_factory=list)
    scope_change: str = "no_change"
    urgency: str = "routine_merge"
    recommended_action: str = "merge_quiet"
    reasoning: str = ""


class CorrelationResult(BaseModel):
    action: str = "new"
    mode: str = "new"
    merge_into_case: Optional[str] = None
    existing_case_context: Optional[dict[str, Any]] = None
    reason: str = ""


class TriageResult(BaseModel):
    alert_id: str
    action: str
    verdict: Optional[str] = None
    severity: Optional[str] = None
    likelihood: Optional[str] = None
    impact_if_true: Optional[str] = None
    mitre_mapping: list[MitreMapping] = Field(default_factory=list)
    reasoning: str = ""
    summary: str = ""
    merge_into_case: Optional[str] = None
    severity_change: Optional[str] = None
    urgency: Optional[str] = None
    evidence_package: dict[str, Any] = Field(default_factory=dict)
    investigation_trace: list[dict[str, Any]] = Field(default_factory=list)
    correlation_result: Optional[dict[str, Any]] = None


class TriageState(TypedDict, total=False):
    canonical_alert: Optional[CanonicalAlert]
    mode: str
    correlation_result: Optional[CorrelationResult]
    existing_case_context: Optional[dict[str, Any]]
    evidence_package: Optional[EvidencePackage]
    delta_evidence: Optional[DeltaEvidence]
    triage_verdict: Optional[TriageVerdict]
    delta_verdict: Optional[DeltaVerdict]
    triage_result: Optional[TriageResult]
