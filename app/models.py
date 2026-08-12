from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass(frozen=True)
class Alert:
    alert_id: str
    title: str
    severity: str
    timestamp: str
    description: str
    user: str = ""
    device: str = ""
    src_ip: str = ""
    application: str = ""

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "Alert":
        return cls(**value)


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    timestamp: str
    source: str
    event_type: str
    user: str = ""
    device: str = ""
    src_ip: str = ""
    application: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "SecurityEvent":
        return cls(**value)


@dataclass(frozen=True)
class GroundTruth:
    verdict: str
    primary_hypothesis: str
    mitre_techniques: List[str]
    evidence_event_ids: List[str]

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "GroundTruth":
        return cls(**value)


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    description: str
    alert: Alert
    events: List[SecurityEvent]
    threat_intel: Dict[str, Dict[str, Any]]
    ground_truth: GroundTruth

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "Scenario":
        return cls(
            scenario_id=value["scenario_id"],
            title=value["title"],
            description=value["description"],
            alert=Alert.from_dict(value["alert"]),
            events=[SecurityEvent.from_dict(event) for event in value["events"]],
            threat_intel=value.get("threat_intel", {}),
            ground_truth=GroundTruth.from_dict(value["ground_truth"]),
        )


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    source: str
    finding: str
    weight: float
    supports: str
    event_ids: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Hypothesis:
    name: str
    description: str
    prior: float
    confidence: float
    status: str
    evidence: List[Evidence] = field(default_factory=list)


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    rationale: str


@dataclass(frozen=True)
class FeatureVector:
    event_count: int
    source_count: int
    unique_users: int
    unique_devices: int
    unique_ips: int
    suspicious_signal_count: int
    anomaly_score: float
    event_type_counts: Dict[str, int]


@dataclass(frozen=True)
class GraphSummary:
    node_count: int
    edge_count: int
    suspicious_paths: List[List[str]]


@dataclass(frozen=True)
class InvestigationReport:
    scenario_id: str
    model_name: str
    alert: Alert
    verdict: str
    risk_score: int
    summary: str
    primary_hypothesis: str
    hypotheses: List[Hypothesis]
    mitre_attack: List[MitreTechnique]
    recommended_actions: List[str]
    timeline: List[str]
    citations: List[str]
    features: FeatureVector
    graph: GraphSummary

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Prediction:
    scenario_id: str
    model_name: str
    verdict: str
    primary_hypothesis: str
    mitre_techniques: List[str]
    cited_event_ids: List[str]
    latency_ms: float = 0.0


@dataclass(frozen=True)
class EvaluationMetrics:
    model_name: str
    scenario_count: int
    verdict_accuracy: float
    attack_recall: float
    benign_specificity: float
    hypothesis_accuracy: float
    technique_precision: float
    technique_recall: float
    citation_precision: float
    evidence_coverage: float
    unsupported_citation_rate: float
    mean_latency_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

