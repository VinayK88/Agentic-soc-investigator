#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.engine import InvestigationEngine  # noqa: E402
from app.scenarios import load_scenarios, scenario_by_id  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run reproducible SOC investigation scenarios")
    parser.add_argument("--scenario", help="Run one scenario ID; default runs all scenarios")
    parser.add_argument("--json", action="store_true", help="Print full JSON reports")
    args = parser.parse_args()

    scenarios = load_scenarios()
    if args.scenario:
        scenarios = [scenario_by_id(args.scenario, scenarios)]

    engine = InvestigationEngine()
    for scenario in scenarios:
        report = engine.investigate(scenario)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        else:
            techniques = ", ".join(item.technique_id for item in report.mitre_attack) or "none"
            print(
                f"{scenario.scenario_id:40} {report.verdict:24} "
                f"risk={report.risk_score:3} hypothesis={report.primary_hypothesis} techniques={techniques}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

