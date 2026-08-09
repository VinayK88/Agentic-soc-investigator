from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]


class Alert(BaseModel):
    alert_id: str
    title: str
    severity: Severity
    user: str
    device: str
    src_ip: str
    timestamp: str
    description: str


class Evidence(BaseModel):
    source: str
    finding: str
    weight: float = Field(ge=-1.0, le=1.0)
    details: dict = Field(default_factory=dict)


class Hypothesis(BaseModel):
    name: str
    description: str
    prior: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    status: Literal["supported", "rejected", "inconclusive"]
    evidence: list[Evidence] = Field(default_factory=list)


class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    rationale: str


class InvestigationReport(BaseModel):
    alert: Alert
    verdict: Literal["benign", "suspicious", "confirmed_compromise"]
    risk_score: int = Field(ge=0, le=100)
    summary: str
    hypotheses: list[Hypothesis]
    mitre_attack: list[MitreTechnique]
    recommended_actions: list[str]
    timeline: list[str]
