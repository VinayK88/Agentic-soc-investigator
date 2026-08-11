from __future__ import annotations

from typing import Iterable, List

from .models import Scenario, SecurityEvent


class ScenarioToolbox:
    """Read-only security tools backed by one reproducible scenario."""

    def __init__(self, scenario: Scenario):
        self.scenario = scenario

    def query_identity(self, user: str) -> List[SecurityEvent]:
        return self._query({"entra", "identity"}, user=user)

    def query_endpoint(self, device: str) -> List[SecurityEvent]:
        return self._query({"endpoint", "edr"}, device=device)

    def query_cloud(self, user: str = "", application: str = "") -> List[SecurityEvent]:
        return self._query({"cloud", "saas"}, user=user, application=application)

    def query_network(self, src_ip: str = "", device: str = "") -> List[SecurityEvent]:
        return self._query({"network", "dns", "proxy"}, src_ip=src_ip, device=device)

    def query_all(self) -> List[SecurityEvent]:
        return list(self.scenario.events)

    def lookup_ip(self, ip_address: str) -> dict:
        return self.scenario.threat_intel.get(
            ip_address,
            {"reputation": "unknown", "score": 0, "tags": []},
        )

    def _query(
        self,
        sources: Iterable[str],
        user: str = "",
        device: str = "",
        src_ip: str = "",
        application: str = "",
    ) -> List[SecurityEvent]:
        allowed = set(sources)
        result = []
        for event in self.scenario.events:
            if event.source not in allowed:
                continue
            if user and event.user != user:
                continue
            if device and event.device != device:
                continue
            if src_ip and event.src_ip != src_ip:
                continue
            if application and event.application != application:
                continue
            result.append(event)
        return result

