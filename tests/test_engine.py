import unittest

from app.engine import InvestigationEngine
from app.scenarios import load_scenarios


class InvestigationEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = InvestigationEngine()

    def test_all_scenarios_match_ground_truth(self):
        for scenario in load_scenarios():
            with self.subTest(scenario=scenario.scenario_id):
                report = self.engine.investigate(scenario)
                self.assertEqual(report.verdict, scenario.ground_truth.verdict)
                self.assertEqual(report.primary_hypothesis, scenario.ground_truth.primary_hypothesis)
                self.assertEqual(
                    {item.technique_id for item in report.mitre_attack},
                    set(scenario.ground_truth.mitre_techniques),
                )

    def test_citations_are_real_events_and_actions_require_human_approval(self):
        for scenario in load_scenarios():
            report = self.engine.investigate(scenario)
            available = {event.event_id for event in scenario.events}
            self.assertTrue(set(report.citations) <= available)
            if report.verdict != "benign":
                self.assertTrue(any("human analyst approval" in item.lower() for item in report.recommended_actions))

    def test_graph_and_features_are_populated(self):
        for scenario in load_scenarios():
            report = self.engine.investigate(scenario)
            self.assertGreater(report.features.event_count, 0)
            self.assertGreater(report.graph.node_count, 0)
            if report.verdict != "benign":
                self.assertTrue(report.graph.suspicious_paths)


if __name__ == "__main__":
    unittest.main()

