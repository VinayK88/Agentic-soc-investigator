#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.evaluation import prompt_record  # noqa: E402
from app.scenarios import load_scenarios  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Export ground-truth-free model prompts as JSONL")
    parser.add_argument("--output", type=Path, help="Write JSONL to this path instead of stdout")
    args = parser.parse_args()

    content = "\n".join(
        json.dumps(prompt_record(scenario), sort_keys=True)
        for scenario in load_scenarios()
    ) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
    else:
        print(content, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
