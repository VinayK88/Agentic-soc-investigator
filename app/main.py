from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .engine import InvestigationEngine
from .evaluation import AlertOnlyAdapter, EvidenceFirstAdapter, PermissiveKeywordAdapter, compare_adapters
from .scenarios import load_scenarios, scenario_by_id


app = FastAPI(
    title="Agentic SOC Investigator",
    version="0.2.0",
    description="Evidence-grounded SOC investigation and evaluation research platform.",
)
engine = InvestigationEngine()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": "0.2.0"}


@app.get("/api/scenarios")
def scenarios() -> list[dict]:
    return [
        {
            "scenario_id": scenario.scenario_id,
            "title": scenario.title,
            "description": scenario.description,
            "is_attack": scenario.ground_truth.verdict != "benign",
        }
        for scenario in load_scenarios()
    ]


@app.post("/api/investigate/{scenario_id}")
def investigate(scenario_id: str) -> dict:
    try:
        scenario = scenario_by_id(scenario_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return engine.investigate(scenario).to_dict()


@app.get("/api/evaluation")
def evaluation() -> list[dict]:
    metrics = compare_adapters(
        [EvidenceFirstAdapter(), AlertOnlyAdapter(), PermissiveKeywordAdapter()],
        load_scenarios(),
    )
    return [item.to_dict() for item in metrics]


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    path = Path(__file__).parent / "static" / "index.html"
    return path.read_text(encoding="utf-8")

