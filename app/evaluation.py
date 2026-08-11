from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from pathlib import Path
from statistics import mean
from typing import Dict, Iterable, List, Sequence, Tuple

from .engine import ACCOUNT_TAKEOVER, BENIGN_ACTIVITY, ENDPOINT_COMPROMISE, OAUTH_ABUSE, InvestigationEngine
from .models import EvaluationMetrics, Prediction, Scenario


class ModelAdapter(ABC):
    """Common interface for deterministic baselines and replayed real-model outputs."""

    name: str

    @abstractmethod
    def predict(self, scenario: Scenario) -> Prediction:
        raise NotImplementedError


class EvidenceFirstAdapter(ModelAdapter):
    name = "evidence-first-v0.2"

    def predict(self, scenario: Scenario) -> Prediction:
        started = time.perf_counter()
        report = InvestigationEngine().investigate(scenario)
        elapsed_ms = (time.perf_counter() - started) * 1000
        return Prediction(
            scenario_id=scenario.scenario_id,
            model_name=self.name,
            verdict=report.verdict,
            primary_hypothesis=report.primary_hypothesis,
            mitre_techniques=[item.technique_id for item in report.mitre_attack],
            cited_event_ids=report.citations,
            latency_ms=elapsed_ms,
        )


class AlertOnlyAdapter(ModelAdapter):
    """Ablation that sees only alert text and cannot cite supporting telemetry."""

    name = "alert-only-ablation"

    def predict(self, scenario: Scenario) -> Prediction:
        started = time.perf_counter()
        text = f"{scenario.alert.title} {scenario.alert.description}".lower()
        if "powershell" in text or "remote authentication" in text:
            hypothesis = ENDPOINT_COMPROMISE
            techniques = ["T1059.001", "T1021.002"]
        elif "oauth" in text or "application" in text:
            hypothesis = ACCOUNT_TAKEOVER
            techniques = ["T1078"]
        elif "approved" in text or "corporate vpn" in text:
            hypothesis = BENIGN_ACTIVITY
            techniques = []
        else:
            hypothesis = ACCOUNT_TAKEOVER
            techniques = ["T1078"]

        # Ambiguous impossible-travel alerts are intentionally over-escalated.
        verdict = "benign" if hypothesis == BENIGN_ACTIVITY else "confirmed_compromise"
        elapsed_ms = (time.perf_counter() - started) * 1000
        return Prediction(
            scenario_id=scenario.scenario_id,
            model_name=self.name,
            verdict=verdict,
            primary_hypothesis=hypothesis,
            mitre_techniques=techniques,
            cited_event_ids=[],
            latency_ms=elapsed_ms,
        )


class PermissiveKeywordAdapter(ModelAdapter):
    """Weak baseline that escalates every security alert as account takeover."""

    name = "permissive-keyword-baseline"

    def predict(self, scenario: Scenario) -> Prediction:
        started = time.perf_counter()
        elapsed_ms = (time.perf_counter() - started) * 1000
        return Prediction(
            scenario_id=scenario.scenario_id,
            model_name=self.name,
            verdict="confirmed_compromise",
            primary_hypothesis=ACCOUNT_TAKEOVER,
            mitre_techniques=["T1078", "T1530"],
            cited_event_ids=[],
            latency_ms=elapsed_ms,
        )


class ReplayPredictionAdapter(ModelAdapter):
    """Load JSONL predictions exported from any external or local LLM.

    This keeps provider credentials and model execution outside the repository while
    preserving an identical scoring contract for all compared models.
    """

    def __init__(self, name: str, path: Path):
        self.name = name
        self._predictions: Dict[str, Prediction] = {}
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            scenario_id = value.get("scenario_id")
            if not scenario_id:
                raise ValueError(f"Missing scenario_id at {path}:{line_number}")
            self._predictions[scenario_id] = Prediction(
                scenario_id=scenario_id,
                model_name=name,
                verdict=value["verdict"],
                primary_hypothesis=value["primary_hypothesis"],
                mitre_techniques=value.get("mitre_techniques", []),
                cited_event_ids=value.get("cited_event_ids", []),
                latency_ms=float(value.get("latency_ms", 0.0)),
            )

    def predict(self, scenario: Scenario) -> Prediction:
        try:
            return self._predictions[scenario.scenario_id]
        except KeyError as exc:
            raise KeyError(f"{self.name} has no prediction for {scenario.scenario_id}") from exc


def evaluate_adapter(adapter: ModelAdapter, scenarios: Sequence[Scenario]) -> EvaluationMetrics:
    predictions = [adapter.predict(scenario) for scenario in scenarios]
    truths = {scenario.scenario_id: scenario.ground_truth for scenario in scenarios}
    events = {
        scenario.scenario_id: {event.event_id for event in scenario.events}
        for scenario in scenarios
    }

    verdict_correct = 0
    attack_true_positive = 0
    attack_count = 0
    benign_true_negative = 0
    benign_count = 0
    hypothesis_correct = 0
    technique_tp = technique_fp = technique_fn = 0
    valid_citations = total_citations = expected_evidence = covered_evidence = 0

    for prediction in predictions:
        truth = truths[prediction.scenario_id]
        verdict_correct += int(prediction.verdict == truth.verdict)
        hypothesis_correct += int(prediction.primary_hypothesis == truth.primary_hypothesis)

        if truth.verdict != "benign":
            attack_count += 1
            attack_true_positive += int(prediction.verdict != "benign")
        else:
            benign_count += 1
            benign_true_negative += int(prediction.verdict == "benign")

        predicted_techniques = set(prediction.mitre_techniques)
        true_techniques = set(truth.mitre_techniques)
        technique_tp += len(predicted_techniques & true_techniques)
        technique_fp += len(predicted_techniques - true_techniques)
        technique_fn += len(true_techniques - predicted_techniques)

        available_events = events[prediction.scenario_id]
        citations = set(prediction.cited_event_ids)
        total_citations += len(citations)
        valid_citations += len(citations & available_events)
        expected = set(truth.evidence_event_ids)
        expected_evidence += len(expected)
        covered_evidence += len(citations & expected)

    count = max(1, len(predictions))
    technique_precision = _safe_ratio(technique_tp, technique_tp + technique_fp)
    technique_recall = _safe_ratio(technique_tp, technique_tp + technique_fn)
    citation_precision = _safe_ratio(valid_citations, total_citations)
    unsupported_rate = _safe_ratio(total_citations - valid_citations, total_citations)

    return EvaluationMetrics(
        model_name=adapter.name,
        scenario_count=len(predictions),
        verdict_accuracy=_rounded(verdict_correct / count),
        attack_recall=_rounded(_safe_ratio(attack_true_positive, attack_count)),
        benign_specificity=_rounded(_safe_ratio(benign_true_negative, benign_count)),
        hypothesis_accuracy=_rounded(hypothesis_correct / count),
        technique_precision=_rounded(technique_precision),
        technique_recall=_rounded(technique_recall),
        citation_precision=_rounded(citation_precision),
        evidence_coverage=_rounded(_safe_ratio(covered_evidence, expected_evidence)),
        unsupported_citation_rate=_rounded(unsupported_rate),
        mean_latency_ms=round(mean(item.latency_ms for item in predictions), 3),
    )


def compare_adapters(
    adapters: Iterable[ModelAdapter],
    scenarios: Sequence[Scenario],
) -> List[EvaluationMetrics]:
    return [evaluate_adapter(adapter, scenarios) for adapter in adapters]


def prompt_record(scenario: Scenario) -> dict:
    """Provider-neutral prompt record for reproducible real-model comparisons."""
    event_schema = [
        {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "source": event.source,
            "event_type": event.event_type,
            "user": event.user,
            "device": event.device,
            "src_ip": event.src_ip,
            "application": event.application,
            "details": event.details,
        }
        for event in scenario.events
    ]
    return {
        "scenario_id": scenario.scenario_id,
        "system": (
            "You are a defensive SOC investigator. Use only supplied evidence. "
            "Return JSON with verdict, primary_hypothesis, mitre_techniques, and cited_event_ids. "
            "Never invent event IDs and do not execute remediation."
        ),
        "input": {
            "alert": scenario.alert.__dict__,
            "events": event_schema,
            "threat_intel": scenario.threat_intel,
        },
        "output_schema": {
            "verdict": "benign | suspicious | confirmed_compromise",
            "primary_hypothesis": "string",
            "mitre_techniques": ["Txxxx"],
            "cited_event_ids": ["event-id"],
        },
    }


def _safe_ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _rounded(value: float) -> float:
    return round(value, 4)

