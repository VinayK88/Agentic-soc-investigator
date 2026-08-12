from __future__ import annotations

from math import exp
from typing import Dict, Iterable, List, Sequence, Tuple

from .analytics import build_features
from .graph import EvidenceGraph
from .models import (
    Evidence,
    Hypothesis,
    InvestigationReport,
    MitreTechnique,
    Scenario,
    SecurityEvent,
)
from .tools import ScenarioToolbox


ACCOUNT_TAKEOVER = "Account takeover and cloud data theft"
ENDPOINT_COMPROMISE = "Endpoint compromise and lateral movement"
OAUTH_ABUSE = "OAuth application abuse"
BENIGN_ACTIVITY = "Benign travel or corporate VPN"


MITRE: Dict[str, MitreTechnique] = {
    "T1078": MitreTechnique(
        "T1078",
        "Valid Accounts",
        "Initial Access / Persistence / Defense Evasion",
        "Suspicious activity used a legitimate identity.",
    ),
    "T1098": MitreTechnique(
        "T1098",
        "Account Manipulation",
        "Persistence",
        "Authentication methods or account settings changed before follow-on activity.",
    ),
    "T1530": MitreTechnique(
        "T1530",
        "Data from Cloud Storage",
        "Collection",
        "Unusual high-volume access to cloud-hosted data was observed.",
    ),
    "T1059.001": MitreTechnique(
        "T1059.001",
        "PowerShell",
        "Execution",
        "Endpoint telemetry contains suspicious PowerShell execution.",
    ),
    "T1003.001": MitreTechnique(
        "T1003.001",
        "LSASS Memory",
        "Credential Access",
        "Endpoint telemetry contains an LSASS access signal.",
    ),
    "T1021.002": MitreTechnique(
        "T1021.002",
        "SMB/Windows Admin Shares",
        "Lateral Movement",
        "A remote service and network logon linked two enterprise devices.",
    ),
    "T1071.001": MitreTechnique(
        "T1071.001",
        "Web Protocols",
        "Command and Control",
        "An unusual outbound web connection followed endpoint execution.",
    ),
    "T1098.003": MitreTechnique(
        "T1098.003",
        "Additional Cloud Roles",
        "Persistence / Privilege Escalation",
        "A newly consented OAuth application received privileged access.",
    ),
    "T1078.004": MitreTechnique(
        "T1078.004",
        "Cloud Accounts",
        "Initial Access / Persistence",
        "Application-only cloud sign-ins used a newly privileged service principal.",
    ),
    "T1114.002": MitreTechnique(
        "T1114.002",
        "Remote Email Collection",
        "Collection",
        "The application accessed multiple mailboxes after consent.",
    ),
}


SIGNAL_RULES: Dict[str, Tuple[str, str, float]] = {
    "risky_signin": (ACCOUNT_TAKEOVER, "High-risk Entra sign-in", 0.75),
    "impossible_travel": (ACCOUNT_TAKEOVER, "Impossible-travel sequence", 0.65),
    "mfa_reset": (ACCOUNT_TAKEOVER, "MFA method changed before follow-on activity", 0.78),
    "mass_download": (ACCOUNT_TAKEOVER, "High-volume cloud download", 0.62),
    "encoded_powershell": (ENDPOINT_COMPROMISE, "Encoded PowerShell execution", 0.80),
    "credential_access": (ENDPOINT_COMPROMISE, "Credential-access behavior", 0.90),
    "remote_service": (ENDPOINT_COMPROMISE, "Remote service creation", 0.76),
    "lateral_logon": (ENDPOINT_COMPROMISE, "Unusual lateral network logon", 0.72),
    "c2_connection": (ENDPOINT_COMPROMISE, "Post-execution command-and-control connection", 0.82),
    "oauth_consent": (OAUTH_ABUSE, "New OAuth application consent", 0.68),
    "high_privilege_grant": (OAUTH_ABUSE, "High-privilege application grant", 0.90),
    "app_only_signin": (OAUTH_ABUSE, "New application-only sign-in", 0.65),
    "mailbox_access": (OAUTH_ABUSE, "Cross-mailbox collection pattern", 0.72),
    "known_vpn": (BENIGN_ACTIVITY, "Known corporate VPN egress", 0.90),
    "approved_travel": (BENIGN_ACTIVITY, "Travel approved in the expected window", 0.85),
    "compliant_device": (BENIGN_ACTIVITY, "Known compliant device", 0.55),
    "normal_download": (BENIGN_ACTIVITY, "Cloud access remained inside the user baseline", 0.48),
}


HYPOTHESIS_DESCRIPTIONS = {
    ACCOUNT_TAKEOVER: "An adversary abused identity credentials or session material and accessed cloud data.",
    ENDPOINT_COMPROMISE: "Attacker-controlled execution on one endpoint enabled credential access and movement to another device.",
    OAUTH_ABUSE: "A malicious or compromised OAuth application obtained durable cloud access.",
    BENIGN_ACTIVITY: "The alert is explained by authorized travel, corporate VPN use, and normal user behavior.",
}


PRIORS = {
    ACCOUNT_TAKEOVER: 0.28,
    ENDPOINT_COMPROMISE: 0.22,
    OAUTH_ABUSE: 0.18,
    BENIGN_ACTIVITY: 0.30,
}


class InvestigationEngine:
    """Deterministic evidence layer used directly and as a guardrail for LLM planners."""

    def investigate(self, scenario: Scenario) -> InvestigationReport:
        toolbox = ScenarioToolbox(scenario)
        timeline = [f"Received {scenario.alert.alert_id}: {scenario.alert.title}"]

        identity = toolbox.query_identity(scenario.alert.user)
        endpoint = toolbox.query_endpoint(scenario.alert.device)
        cloud = toolbox.query_cloud(scenario.alert.user, scenario.alert.application)
        network = toolbox.query_network(scenario.alert.src_ip, scenario.alert.device)
        events = toolbox.query_all()
        timeline.extend(
            [
                f"Identity query returned {len(identity)} events",
                f"Endpoint query returned {len(endpoint)} events",
                f"Cloud query returned {len(cloud)} events",
                f"Network query returned {len(network)} events",
            ]
        )

        evidence = self._collect_evidence(events, toolbox.lookup_ip(scenario.alert.src_ip))
        hypotheses = [
            self._hypothesis(name, evidence)
            for name in (ACCOUNT_TAKEOVER, ENDPOINT_COMPROMISE, OAUTH_ABUSE, BENIGN_ACTIVITY)
        ]
        attack_hypotheses = [hypothesis for hypothesis in hypotheses if hypothesis.name != BENIGN_ACTIVITY]
        leading_attack = max(attack_hypotheses, key=lambda item: item.confidence)
        benign = next(item for item in hypotheses if item.name == BENIGN_ACTIVITY)

        risk = round(100 * leading_attack.confidence * (1.0 - 0.62 * benign.confidence))
        risk = max(0, min(100, risk))
        if risk >= 70:
            verdict = "confirmed_compromise"
        elif risk >= 35:
            verdict = "suspicious"
        else:
            verdict = "benign"

        primary = benign if verdict == "benign" else leading_attack
        techniques = self._map_mitre(events)
        citations = sorted({event_id for item in primary.evidence for event_id in item.event_ids})
        features = build_features(events)
        graph = EvidenceGraph.from_events(events).summary()
        timeline.append(
            f"Correlated {features.event_count} events across {features.source_count} sources; anomaly={features.anomaly_score:.2f}"
        )
        timeline.append(f"Completed with verdict={verdict}, risk={risk}, hypothesis={primary.name}")

        return InvestigationReport(
            scenario_id=scenario.scenario_id,
            model_name="evidence-first-v0.2",
            alert=scenario.alert,
            verdict=verdict,
            risk_score=risk,
            summary=(
                f"{verdict.replace('_', ' ').title()} with modeled risk {risk}/100. "
                f"Leading hypothesis: {primary.name} ({primary.confidence:.0%}). "
                f"The conclusion cites {len(citations)} scenario events."
            ),
            primary_hypothesis=primary.name,
            hypotheses=hypotheses,
            mitre_attack=techniques,
            recommended_actions=self._actions(verdict, primary.name),
            timeline=timeline,
            citations=citations,
            features=features,
            graph=graph,
        )

    def _collect_evidence(
        self,
        events: Sequence[SecurityEvent],
        threat_intel: dict,
    ) -> List[Evidence]:
        collected: List[Evidence] = []
        has_oauth_sequence = any(
            event.event_type in {"oauth_consent", "high_privilege_grant", "app_only_signin"}
            for event in events
        )
        for event in events:
            rule = SIGNAL_RULES.get(event.event_type)
            if not rule:
                continue
            hypothesis, finding, weight = rule
            collected.append(
                Evidence(
                    evidence_id=f"ev-{event.event_id}",
                    source=event.source,
                    finding=finding,
                    weight=weight,
                    supports=hypothesis,
                    event_ids=[event.event_id],
                    details=event.details,
                )
            )
            if event.event_type == "mass_download" and has_oauth_sequence:
                collected.append(
                    Evidence(
                        evidence_id=f"ev-{event.event_id}-oauth",
                        source=event.source,
                        finding="High-volume cloud collection performed by the newly privileged application",
                        weight=0.66,
                        supports=OAUTH_ABUSE,
                        event_ids=[event.event_id],
                        details=event.details,
                    )
                )

        reputation = threat_intel.get("reputation")
        if reputation == "malicious":
            collected.append(
                Evidence(
                    evidence_id="ti-source-ip-malicious",
                    source="threat_intelligence",
                    finding="Source IP has malicious reputation",
                    weight=0.72,
                    supports=ACCOUNT_TAKEOVER,
                    details=threat_intel,
                )
            )
            collected.append(
                Evidence(
                    evidence_id="ti-contradicts-benign",
                    source="threat_intelligence",
                    finding="Malicious source reputation contradicts the benign explanation",
                    weight=-0.70,
                    supports=BENIGN_ACTIVITY,
                    details=threat_intel,
                )
            )
        elif reputation == "benign":
            collected.append(
                Evidence(
                    evidence_id="ti-source-ip-benign",
                    source="threat_intelligence",
                    finding="Source IP matches approved enterprise infrastructure",
                    weight=0.62,
                    supports=BENIGN_ACTIVITY,
                    details=threat_intel,
                )
            )
        return collected

    def _hypothesis(self, name: str, evidence: Iterable[Evidence]) -> Hypothesis:
        relevant = [item for item in evidence if item.supports == name]
        strength = sum(item.weight for item in relevant)
        prior = PRIORS[name]
        centered_prior = (prior - 0.5) * 2.4
        confidence = self._sigmoid(centered_prior + 1.85 * strength)
        confidence = round(max(0.01, min(0.99, confidence)), 4)
        status = "supported" if confidence >= 0.68 else "rejected" if confidence < 0.24 else "inconclusive"
        return Hypothesis(
            name=name,
            description=HYPOTHESIS_DESCRIPTIONS[name],
            prior=prior,
            confidence=confidence,
            status=status,
            evidence=relevant,
        )

    @staticmethod
    def _sigmoid(value: float) -> float:
        return 1.0 / (1.0 + exp(-value))

    @staticmethod
    def _map_mitre(events: Iterable[SecurityEvent]) -> List[MitreTechnique]:
        event_types = {event.event_type for event in events}
        technique_ids: List[str] = []
        mapping = {
            "risky_signin": "T1078",
            "impossible_travel": "T1078",
            "mfa_reset": "T1098",
            "mass_download": "T1530",
            "encoded_powershell": "T1059.001",
            "credential_access": "T1003.001",
            "remote_service": "T1021.002",
            "lateral_logon": "T1021.002",
            "c2_connection": "T1071.001",
            "oauth_consent": "T1098.003",
            "high_privilege_grant": "T1098.003",
            "app_only_signin": "T1078.004",
            "mailbox_access": "T1114.002",
        }
        for event_type in sorted(event_types):
            technique_id = mapping.get(event_type)
            if technique_id and technique_id not in technique_ids:
                technique_ids.append(technique_id)
        return [MITRE[technique_id] for technique_id in technique_ids]

    @staticmethod
    def _actions(verdict: str, primary_hypothesis: str) -> List[str]:
        if verdict == "benign":
            return [
                "Validate the approved travel or VPN record, document the evidence, and close the alert.",
                "Retain the case as a negative-control example for future evaluation.",
            ]
        actions = [
            "Preserve the cited identity, endpoint, cloud, and network telemetry.",
            "Require human analyst approval before any containment action.",
        ]
        if primary_hypothesis == ACCOUNT_TAKEOVER:
            actions.extend(
                [
                    "Revoke active sessions and refresh tokens for the affected identity.",
                    "Review MFA methods, OAuth grants, mailbox rules, and cloud-file access.",
                ]
            )
        elif primary_hypothesis == ENDPOINT_COMPROMISE:
            actions.extend(
                [
                    "Isolate corroborated devices using an approved response workflow.",
                    "Collect process, logon, credential-access, and network evidence before remediation.",
                ]
            )
        elif primary_hypothesis == OAUTH_ABUSE:
            actions.extend(
                [
                    "Disable the application or service principal after analyst confirmation.",
                    "Revoke grants and tokens, then review mailbox and file access performed by the application.",
                ]
            )
        return actions
