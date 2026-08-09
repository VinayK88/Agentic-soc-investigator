from app.engine import InvestigationEngine
from app.models import Alert


def malicious_alert():
    return Alert(
        alert_id="T-1",
        title="Suspicious identity activity",
        severity="high",
        user="maya.chen@contoso.example",
        device="FIN-LT-044",
        src_ip="203.0.113.66",
        timestamp="2026-08-09T10:34:00Z",
        description="Synthetic test alert",
    )


def test_detects_high_risk_compromise():
    report = InvestigationEngine().investigate(malicious_alert())
    assert report.verdict == "confirmed_compromise"
    assert report.risk_score >= 75
    assert any(t.technique_id == "T1078" for t in report.mitre_attack)
    assert any(h.name == "Account takeover" and h.confidence > 0.8 for h in report.hypotheses)


def test_report_has_human_approval_language():
    report = InvestigationEngine().investigate(malicious_alert())
    assert any("human analyst approval" in x.lower() for x in report.recommended_actions)
