# Contributing

Contributions are welcome for defensive detection logic, synthetic or properly licensed public datasets, evaluation cases, ATT&CK mappings, explainability, tests, and read-only integrations.

1. Create a feature branch.
2. Add or update tests for behavior changes.
3. Run `python -m unittest discover -s tests -v`.
4. Run `python scripts/compare_models.py` when changing investigation or scoring behavior.
5. Open a pull request describing data provenance, expected behavior, and validation.

Do not contribute exploit delivery, credential harvesting, destructive actions, or automation against systems without explicit authorization.

