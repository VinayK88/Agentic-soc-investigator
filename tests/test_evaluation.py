import json
import tempfile
import unittest
from pathlib import Path

from app.evaluation import (
    AlertOnlyAdapter,
    EvidenceFirstAdapter,
    ReplayPredictionAdapter,
    evaluate_adapter,
    prompt_record,
)
from app.scenarios import load_scenarios


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.scenarios = load_scenarios()

    def test_evidence_first_baseline_is_perfect_on_the_fixture_set(self):
        metrics = evaluate_adapter(EvidenceFirstAdapter(), self.scenarios)
        self.assertEqual(metrics.verdict_accuracy, 1.0)
        self.assertEqual(metrics.benign_specificity, 1.0)
        self.assertEqual(metrics.hypothesis_accuracy, 1.0)
        self.assertEqual(metrics.technique_precision, 1.0)
        self.assertEqual(metrics.technique_recall, 1.0)
        self.assertEqual(metrics.citation_precision, 1.0)
        self.assertEqual(metrics.evidence_coverage, 1.0)

    def test_alert_only_ablation_loses_evidence_coverage(self):
        metrics = evaluate_adapter(AlertOnlyAdapter(), self.scenarios)
        self.assertLess(metrics.hypothesis_accuracy, 1.0)
        self.assertEqual(metrics.evidence_coverage, 0.0)

    def test_replay_adapter_uses_same_contract(self):
        rows = []
        for scenario in self.scenarios:
            rows.append(
                json.dumps(
                    {
                        "scenario_id": scenario.scenario_id,
                        "verdict": scenario.ground_truth.verdict,
                        "primary_hypothesis": scenario.ground_truth.primary_hypothesis,
                        "mitre_techniques": scenario.ground_truth.mitre_techniques,
                        "cited_event_ids": scenario.ground_truth.evidence_event_ids,
                    }
                )
            )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "predictions.jsonl"
            path.write_text("\n".join(rows), encoding="utf-8")
            metrics = evaluate_adapter(ReplayPredictionAdapter("fixture-model", path), self.scenarios)
        self.assertEqual(metrics.verdict_accuracy, 1.0)
        self.assertEqual(metrics.evidence_coverage, 1.0)

    def test_prompt_bundle_does_not_reveal_ground_truth(self):
        record = prompt_record(self.scenarios[0])
        serialized = json.dumps(record)
        self.assertNotIn("ground_truth", serialized)
        self.assertIn("cited_event_ids", serialized)


if __name__ == "__main__":
    unittest.main()

