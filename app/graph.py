from __future__ import annotations

from collections import defaultdict, deque
from typing import Dict, Iterable, List, Set, Tuple

from .models import GraphSummary, SecurityEvent


EVENT_TO_TECHNIQUE = {
    "risky_signin": "T1078",
    "impossible_travel": "T1078",
    "mfa_reset": "T1098",
    "mass_download": "T1530",
    "encoded_powershell": "T1059.001",
    "credential_access": "T1003.001",
    "remote_service": "T1021.002",
    "lateral_logon": "T1021",
    "c2_connection": "T1071.001",
    "oauth_consent": "T1098.003",
    "high_privilege_grant": "T1098.003",
    "app_only_signin": "T1078.004",
    "mailbox_access": "T1114.002",
}


class EvidenceGraph:
    def __init__(self) -> None:
        self.nodes: Set[str] = set()
        self.edges: Set[Tuple[str, str, str]] = set()
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)

    def add_edge(self, source: str, relation: str, target: str) -> None:
        if not source or not target:
            return
        self.nodes.update({source, target})
        self.edges.add((source, relation, target))
        self.adjacency[source].add(target)
        self.adjacency[target].add(source)

    @classmethod
    def from_events(cls, events: Iterable[SecurityEvent]) -> "EvidenceGraph":
        graph = cls()
        for event in events:
            event_node = f"event:{event.event_id}"
            graph.nodes.add(event_node)
            for prefix, value in (
                ("user", event.user),
                ("device", event.device),
                ("ip", event.src_ip),
                ("app", event.application),
            ):
                if value:
                    graph.add_edge(f"{prefix}:{value}", "observed_in", event_node)
            technique = EVENT_TO_TECHNIQUE.get(event.event_type)
            if technique:
                graph.add_edge(event_node, "indicates", f"attack:{technique}")
        return graph

    def shortest_path(self, source: str, target: str) -> List[str]:
        if source not in self.nodes or target not in self.nodes:
            return []
        queue = deque([(source, [source])])
        seen = {source}
        while queue:
            node, path = queue.popleft()
            if node == target:
                return path
            for neighbor in sorted(self.adjacency[node]):
                if neighbor not in seen:
                    seen.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        return []

    def summary(self) -> GraphSummary:
        entity_nodes = sorted(
            node for node in self.nodes if node.startswith(("user:", "device:", "ip:", "app:"))
        )
        technique_nodes = sorted(node for node in self.nodes if node.startswith("attack:"))
        paths: List[List[str]] = []
        for entity in entity_nodes:
            for technique in technique_nodes:
                path = self.shortest_path(entity, technique)
                if path and path not in paths:
                    paths.append(path)
                if len(paths) >= 8:
                    break
            if len(paths) >= 8:
                break
        return GraphSummary(
            node_count=len(self.nodes),
            edge_count=len(self.edges),
            suspicious_paths=paths,
        )

