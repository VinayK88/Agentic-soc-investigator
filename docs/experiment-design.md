# Experiment design

## Research question

Does evidence-first investigation improve correctness, specificity, ATT&CK mapping, and evidentiary grounding relative to alert-only or permissive keyword reasoning?

## Cases

The checked-in fixture set contains three attacks and one negative control:

1. Identity takeover followed by cloud collection
2. Endpoint execution, credential access, and lateral movement
3. OAuth consent abuse and mailbox/file collection
4. Benign travel through a known corporate VPN

Each case contains a normalized alert, cross-source events, synthetic threat-intelligence context, an expected verdict, primary hypothesis, ATT&CK techniques, and relevant evidence IDs.

## Metrics

- **Verdict accuracy:** exact match against the expected verdict.
- **Attack recall:** fraction of attack cases not classified as benign.
- **Benign specificity:** fraction of negative controls classified as benign.
- **Hypothesis accuracy:** exact match of the primary investigation hypothesis.
- **Technique precision/recall:** set comparison of ATT&CK technique IDs.
- **Citation precision:** cited event IDs that actually exist in the case.
- **Evidence coverage:** expected evidence IDs cited by the model.
- **Unsupported-citation rate:** cited IDs not present in the supplied case.
- **Latency:** measured for operational visibility, but not interpreted for the tiny offline fixtures.

## Baselines

- `evidence-first-v0.2` uses the complete deterministic evidence pipeline.
- `alert-only-ablation` sees only alert title and description.
- `permissive-keyword-baseline` escalates every alert and supplies generic ATT&CK mappings.

These are system ablations, not measurements of named commercial LLMs.

## Real-model protocol

1. Export provider-neutral prompt records with `python scripts/export_model_prompts.py`.
2. Run the identical records against each model under test.
3. Save one JSON object per line with the required prediction schema.
4. Compare using `python scripts/compare_models.py --prediction MODEL=predictions.jsonl`.
5. For nondeterministic models, run at least five independent repetitions and report distributions rather than only the best run.
6. Keep model version, date, temperature/reasoning configuration, prompt hash, latency, and token cost in the experiment log.

## Threats to validity

The checked-in dataset is tiny, synthetic, and intentionally legible. Perfect fixture performance demonstrates implementation consistency, not production accuracy. Before making effectiveness claims, expand with independently labeled public/authorized data, blind case authoring, more benign controls, missing-telemetry cases, adversarial evidence, class imbalance, and analyst review.

