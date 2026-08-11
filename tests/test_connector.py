import json
import unittest
from unittest.mock import patch

from app.connectors.defender_graph import DefenderGraphConnector


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(
            {
                "schema": [{"name": "Timestamp", "type": "DateTime"}],
                "results": [{"Timestamp": "2026-08-11T00:00:00Z"}],
            }
        ).encode("utf-8")


class ConnectorTests(unittest.TestCase):
    def test_token_is_required(self):
        with self.assertRaises(ValueError):
            DefenderGraphConnector("")

    @patch("app.connectors.defender_graph.urlopen", return_value=_Response())
    def test_query_shape_and_result(self, mocked_urlopen):
        connector = DefenderGraphConnector("synthetic-token")
        result = connector.run_hunting_query("DeviceProcessEvents | take 1", "P1D")
        self.assertEqual(len(result.results), 1)
        request = mocked_urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["Timespan"], "P1D")
        self.assertNotIn("synthetic-token", request.data.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()

