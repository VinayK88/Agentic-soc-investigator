from __future__ import annotations

from pathlib import Path
import json


DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "synthetic_security_data.json"


class SecurityToolbox:
    """Read-only defensive tools backed by synthetic telemetry."""

    def __init__(self, data_path: Path = DATA_PATH):
        self.data = json.loads(data_path.read_text())

    def query_siem(self, user: str, src_ip: str) -> list[dict]:
        return [
            event for event in self.data["siem_events"]
            if event.get("user") == user or event.get("src_ip") == src_ip
        ]

    def query_edr(self, device: str) -> list[dict]:
        return [event for event in self.data["edr_events"] if event.get("device") == device]

    def query_identity(self, user: str) -> list[dict]:
        return [event for event in self.data["identity_events"] if event.get("user") == user]

    def lookup_ip(self, ip: str) -> dict:
        return self.data["threat_intel"].get(ip, {"reputation": "unknown", "score": 0, "tags": []})
