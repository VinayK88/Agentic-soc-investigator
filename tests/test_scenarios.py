import unittest

from app.scenarios import load_scenarios, scenario_by_id


class ScenarioTests(unittest.TestCase):
    def test_dataset_contains_three_attacks_and_one_negative_control(self):
        scenarios = load_scenarios()
        self.assertEqual(len(scenarios), 4)
        attacks = [scenario for scenario in scenarios if scenario.ground_truth.verdict != "benign"]
        controls = [scenario for scenario in scenarios if scenario.ground_truth.verdict == "benign"]
        self.assertEqual(len(attacks), 3)
        self.assertEqual(len(controls), 1)

    def test_event_ids_are_unique_inside_each_scenario(self):
        for scenario in load_scenarios():
            event_ids = [event.event_id for event in scenario.events]
            self.assertEqual(len(event_ids), len(set(event_ids)), scenario.scenario_id)
            self.assertTrue(set(scenario.ground_truth.evidence_event_ids) <= set(event_ids))

    def test_lookup_by_id(self):
        scenario = scenario_by_id("identity-takeover-cloud-exfil")
        self.assertEqual(scenario.alert.alert_id, "ALRT-IDENTITY-001")


if __name__ == "__main__":
    unittest.main()

