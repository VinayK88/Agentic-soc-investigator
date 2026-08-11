from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from .models import Scenario


DEFAULT_SCENARIO_DIR = Path(__file__).resolve().parents[1] / "data" / "scenarios"


def load_scenario(path: Path) -> Scenario:
    return Scenario.from_dict(json.loads(path.read_text(encoding="utf-8")))


def load_scenarios(directory: Path = DEFAULT_SCENARIO_DIR) -> List[Scenario]:
    return [load_scenario(path) for path in sorted(directory.glob("*.json"))]


def scenario_by_id(scenario_id: str, scenarios: Iterable[Scenario] | None = None) -> Scenario:
    for scenario in scenarios or load_scenarios():
        if scenario.scenario_id == scenario_id:
            return scenario
    raise KeyError(f"Unknown scenario: {scenario_id}")

