from __future__ import annotations

from math import exp

from .models import Alert, Evidence, Hypothesis, InvestigationReport, MitreTechnique
from .tools import SecurityToolbox


MITRE = {
    "valid_accounts": MitreTechnique(
        technique_id="T1078", name="Valid Accounts", tactic="Defense Evasion / Persistence",
        rationale="Suspicious authentication behavior using a legitimate account."
    ),
    "external_remote_services": MitreTechnique(
        technique_id="T1133", name="External Remote Services", tactic="Persistence / Initial Access",
        rationale="Remote sign-in activity originated from an unusual external source."
    ),
    "powershell": MitreTechnique(
        technique_id="T1059.001", name="PowerShell", tactic="Execution",
        rationale="Endpoint telemetry contains suspicious PowerShell execution."
    ),
    "cloud_data": MitreTechnique(
        technique_id="T1530", name="Data from Cloud Storage", tactic="Collection",
        rationale="Large cloud-data access followed the suspicious identity activity."
    ),
}


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + exp(-x))


class InvestigationEngine:
    def __init__(self, toolbox: SecurityToolbox | None = None):
        self.tools = toolbox or SecurityToolbox()

    def investigate(self, alert: Alert) -> InvestigationReport:
        timeline: list[str] = [f"Received alert {alert.alert_id}: {alert.title}"]
        siem = self.tools.query_siem(alert.user, alert.src_ip)
        timeline.append(f"SIEM query returned {len(siem)} correlated events")
        identity = self.tools.query_identity(alert.user)
        timeline.append(f"Identity query returned {len(identity)} events")
        edr = self.tools.query_edr(alert.device)
        timeline.append(f"EDR query returned {len(edr)} events")
        intel = self.tools.lookup_ip(alert.src_ip)
        timeline.append(f"Threat-intel reputation for {alert.src_ip}: {intel['reputation']}")

        hypotheses = [
            self._account_takeover(alert, identity, siem, intel),
            self._endpoint_compromise(edr),
            self._benign_travel(identity, intel),
        ]

        attack = max(hypotheses, key=lambda h: h.confidence)
        compromise_conf = max(
            h.confidence for h in hypotheses if h.name in {"Account takeover", "Endpoint compromise"}
        )
        benign_conf = next(h.confidence for h in hypotheses if h.name == "Benign travel / VPN")

        risk = round(100 * max(0.0, min(1.0, compromise_conf * (1.0 - 0.45 * benign_conf))))
        if risk >= 75:
            verdict = "confirmed_compromise"
        elif risk >= 40:
            verdict = "suspicious"
        else:
            verdict = "benign"

        mitre = self._map_mitre(identity, edr, siem, intel)
        actions = self._actions(verdict, identity, edr)
        summary = (
            f"{verdict.replace('_', ' ').title()} with modeled risk {risk}/100. "
            f"Highest-confidence hypothesis: {attack.name} ({attack.confidence:.0%})."
        )
        timeline.append(f"Investigation completed with verdict={verdict}, risk={risk}")

        return InvestigationReport(
            alert=alert,
            verdict=verdict,
            risk_score=risk,
            summary=summary,
            hypotheses=hypotheses,
            mitre_attack=mitre,
            recommended_actions=actions,
            timeline=timeline,
        )

    def _score(self, prior: float, evidence: list[Evidence]) -> float:
        # Logit-like update for an interpretable deterministic MVP.
        strength = sum(e.weight for e in evidence)
        prior_centered = (prior - 0.5) * 2.2
        return max(0.01, min(0.99, sigmoid(prior_centered + 2.0 * strength)))

    def _account_takeover(self, alert, identity, siem, intel) -> Hypothesis:
        evidence: list[Evidence] = []
        if intel.get("reputation") == "malicious":
            evidence.append(Evidence(source="Threat Intel", finding="Source IP is known malicious", weight=0.9, details=intel))
        if any(e.get("type") == "impossible_travel" for e in identity):
            evidence.append(Evidence(source="Entra", finding="Impossible-travel signal observed", weight=0.65))
        if any(e.get("type") == "mfa_reset" for e in identity):
            evidence.append(Evidence(source="Entra", finding="MFA method changed shortly before alert", weight=0.75))
        if any(e.get("type") == "mass_download" for e in siem):
            evidence.append(Evidence(source="SIEM", finding="Large cloud download after authentication", weight=0.7))
        confidence = self._score(0.40, evidence)
        return Hypothesis(
            name="Account takeover",
            description="An attacker obtained or abused valid identity credentials/session material.",
            prior=0.40,
            confidence=confidence,
            status="supported" if confidence >= 0.65 else "inconclusive",
            evidence=evidence,
        )

    def _endpoint_compromise(self, edr) -> Hypothesis:
        evidence: list[Evidence] = []
        if any(e.get("type") == "suspicious_powershell" for e in edr):
            evidence.append(Evidence(source="EDR", finding="Encoded PowerShell execution detected", weight=0.8))
        if any(e.get("type") == "credential_access" for e in edr):
            evidence.append(Evidence(source="EDR", finding="Credential-access behavior observed", weight=0.9))
        confidence = self._score(0.25, evidence)
        return Hypothesis(
            name="Endpoint compromise",
            description="The endpoint may be executing attacker-controlled code.",
            prior=0.25,
            confidence=confidence,
            status="supported" if confidence >= 0.65 else "inconclusive",
            evidence=evidence,
        )

    def _benign_travel(self, identity, intel) -> Hypothesis:
        evidence: list[Evidence] = []
        if any(e.get("type") == "known_vpn" for e in identity):
            evidence.append(Evidence(source="Entra", finding="Sign-in matched corporate VPN egress", weight=0.75))
        if intel.get("reputation") == "benign":
            evidence.append(Evidence(source="Threat Intel", finding="Source IP has benign reputation", weight=0.55))
        if intel.get("reputation") == "malicious":
            evidence.append(Evidence(source="Threat Intel", finding="Malicious reputation contradicts benign-travel theory", weight=-0.75))
        confidence = self._score(0.30, evidence)
        return Hypothesis(
            name="Benign travel / VPN",
            description="The alert may be explained by legitimate travel or enterprise VPN use.",
            prior=0.30,
            confidence=confidence,
            status="supported" if confidence >= 0.65 else ("rejected" if confidence < 0.30 else "inconclusive"),
            evidence=evidence,
        )

    def _map_mitre(self, identity, edr, siem, intel):
        techniques: list[MitreTechnique] = []
        if identity:
            techniques.append(MITRE["valid_accounts"])
        if intel.get("reputation") == "malicious":
            techniques.append(MITRE["external_remote_services"])
        if any(e.get("type") == "suspicious_powershell" for e in edr):
            techniques.append(MITRE["powershell"])
        if any(e.get("type") == "mass_download" for e in siem):
            techniques.append(MITRE["cloud_data"])
        return techniques

    def _actions(self, verdict, identity, edr):
        if verdict == "benign":
            return ["Close after analyst validation and document the benign explanation."]
        actions = [
            "Revoke active sessions and refresh tokens for the affected identity.",
            "Require phishing-resistant MFA before restoring normal access.",
            "Review recent OAuth grants, mailbox rules, and cloud-file activity.",
        ]
        if edr:
            actions.append("Isolate the device if endpoint telemetry corroborates malicious execution.")
        actions.append("Preserve relevant telemetry and escalate for human analyst approval before remediation.")
        return actions
