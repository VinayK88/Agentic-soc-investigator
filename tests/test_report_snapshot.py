import json
import unittest
from pathlib import Path

from app.evaluation import AlertOnlyAdapter, EvidenceFirstAdapter, PermissiveKeywordAdapter, compare_adapters
from app.scenarios import load_scenarios


ROOT = Path(__file__).resolve().parents[1]


class ReportSnapshotTests(unittest.TestCase):
    def test_offline_report_matches_current_evaluation(self) -> None:
        expected = json.loads((ROOT / "reports" / "offline-baseline.json").read_text(encoding="utf-8"))
        actual = [
            {
                key: round(value, 4) if isinstance(value, float) else value
                for key, value in metric.to_dict().items()
                if key != "mean_latency_ms"
            }
            for metric in compare_adapters(
                [EvidenceFirstAdapter(), AlertOnlyAdapter(), PermissiveKeywordAdapter()],
                load_scenarios(),
            )
        ]
        self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
