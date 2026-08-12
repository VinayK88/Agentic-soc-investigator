#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.evaluation import (  # noqa: E402
    AlertOnlyAdapter,
    EvidenceFirstAdapter,
    PermissiveKeywordAdapter,
    ReplayPredictionAdapter,
    compare_adapters,
)
from app.scenarios import load_scenarios  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare investigation models with one scoring contract")
    parser.add_argument(
        "--prediction",
        action="append",
        default=[],
        metavar="MODEL=JSONL",
        help="Add replayed real-model predictions; may be repeated",
    )
    parser.add_argument("--json", action="store_true", help="Emit metrics as JSON")
    args = parser.parse_args()

    adapters = [EvidenceFirstAdapter(), AlertOnlyAdapter(), PermissiveKeywordAdapter()]
    for value in args.prediction:
        if "=" not in value:
            parser.error("--prediction must be MODEL=JSONL")
        name, path = value.split("=", 1)
        adapters.append(ReplayPredictionAdapter(name, Path(path)))

    metrics = compare_adapters(adapters, load_scenarios())
    if args.json:
        print(json.dumps([item.to_dict() for item in metrics], indent=2, sort_keys=True))
        return 0

    columns = [
        ("model", 30),
        ("verdict", 8),
        ("attack", 8),
        ("benign", 8),
        ("hyp", 8),
        ("tech-p", 8),
        ("tech-r", 8),
        ("cite-p", 8),
        ("coverage", 9),
    ]
    print(" ".join(label.ljust(width) for label, width in columns))
    print(" ".join("-" * width for _, width in columns))
    for item in metrics:
        values = [
            item.model_name,
            f"{item.verdict_accuracy:.0%}",
            f"{item.attack_recall:.0%}",
            f"{item.benign_specificity:.0%}",
            f"{item.hypothesis_accuracy:.0%}",
            f"{item.technique_precision:.0%}",
            f"{item.technique_recall:.0%}",
            f"{item.citation_precision:.0%}",
            f"{item.evidence_coverage:.0%}",
        ]
        print(" ".join(value.ljust(width) for value, (_, width) in zip(values, columns)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

