from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


GRAPH_HUNTING_ENDPOINT = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"


@dataclass(frozen=True)
class HuntingQueryResult:
    schema: List[Dict[str, Any]]
    results: List[Dict[str, Any]]


class DefenderGraphConnector:
    """Minimal read-only Microsoft Graph advanced-hunting connector.

    The caller supplies an access token with the least-privileged
    ThreatHunting.Read.All permission. Tokens are never logged or persisted.
    """

    def __init__(self, access_token: str, endpoint: str = GRAPH_HUNTING_ENDPOINT, timeout: int = 60):
        if not access_token:
            raise ValueError("A Microsoft Graph access token is required")
        self._access_token = access_token
        self.endpoint = endpoint
        self.timeout = timeout

    @classmethod
    def from_environment(cls) -> "DefenderGraphConnector":
        return cls(os.environ.get("DEFENDER_GRAPH_ACCESS_TOKEN", ""))

    def run_hunting_query(self, query: str, timespan: str = "P30D") -> HuntingQueryResult:
        if not query.strip():
            raise ValueError("KQL query must not be empty")
        if len(query) > 100_000:
            raise ValueError("KQL query exceeds the local safety limit")

        payload = json.dumps({"Query": query, "Timespan": timespan}).encode("utf-8")
        request = Request(
            self.endpoint,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._access_token}",
                "Content-Type": "application/json; charset=utf-8",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            # Do not include response bodies because they can contain tenant context.
            raise RuntimeError(f"Microsoft Graph returned HTTP {exc.code}") from exc
        except URLError as exc:
            raise RuntimeError("Unable to reach Microsoft Graph") from exc

        return HuntingQueryResult(
            schema=list(body.get("schema", [])),
            results=list(body.get("results", [])),
        )

