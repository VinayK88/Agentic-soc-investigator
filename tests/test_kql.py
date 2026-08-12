import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KQL_DIR = ROOT / "detections" / "kql"


class KqlContentTests(unittest.TestCase):
    def test_three_queries_exist(self):
        self.assertEqual(len(list(KQL_DIR.glob("*.kql"))), 3)

    def test_queries_use_current_schema_and_are_bounded(self):
        contents = "\n".join(path.read_text(encoding="utf-8") for path in KQL_DIR.glob("*.kql"))
        self.assertIn("EntraIdSignInEvents", contents)
        self.assertIn("CloudAppEvents", contents)
        self.assertIn("DeviceProcessEvents", contents)
        self.assertIn("DeviceLogonEvents", contents)
        self.assertNotIn("AADSignInEventsBeta", contents)
        for path in KQL_DIR.glob("*.kql"):
            query = path.read_text(encoding="utf-8")
            self.assertIn("ago(", query, path.name)
            self.assertIn("project", query, path.name)


if __name__ == "__main__":
    unittest.main()

