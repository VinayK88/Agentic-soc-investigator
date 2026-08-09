from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from .engine import InvestigationEngine
from .models import Alert, InvestigationReport

app = FastAPI(
    title="Agentic SOC Investigator",
    version="0.1.0",
    description="Defensive, simulation-only autonomous SOC investigation MVP.",
)
engine = InvestigationEngine()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/investigate", response_model=InvestigationReport)
def investigate(alert: Alert):
    return engine.investigate(alert)


@app.get("/demo-alert")
def demo_alert():
    return {
        "alert_id": "ALRT-2026-001",
        "title": "Suspicious Entra sign-in followed by cloud download",
        "severity": "high",
        "user": "maya.chen@contoso.example",
        "device": "FIN-LT-044",
        "src_ip": "203.0.113.66",
        "timestamp": "2026-08-09T10:34:00Z",
        "description": "Impossible travel and unusual data access were observed for a finance identity."
    }


@app.get("/", response_class=HTMLResponse)
def home():
    html_path = Path(__file__).parent / "static" / "index.html"
    return html_path.read_text()
