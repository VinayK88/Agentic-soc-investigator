# Comparing multiple models

The repository does not embed provider credentials or fabricate live-model scores. Instead, it exports one provider-neutral prompt bundle and evaluates replayed predictions using the same scoring code as the offline baselines.

## Export prompts

```bash
python scripts/export_model_prompts.py > prompts.jsonl
```

Ground truth is intentionally excluded from exported records.

## Prediction schema

Save one JSON object per line:

```json
{
  "scenario_id": "identity-takeover-cloud-exfil",
  "verdict": "confirmed_compromise",
  "primary_hypothesis": "Account takeover and cloud data theft",
  "mitre_techniques": ["T1078", "T1098", "T1530"],
  "cited_event_ids": ["id-001", "id-002", "id-003", "id-004"],
  "latency_ms": 842.4
}
```

## Score one or more models

```bash
python scripts/compare_models.py \
  --prediction model-a=experiments/model-a.jsonl \
  --prediction model-b=experiments/model-b.jsonl
```

The model name is supplied on the command line, so the prediction file remains portable. Invalid or invented event IDs reduce citation precision and increase unsupported-citation rate.

## Minimum experiment log

Record the model's immutable version or deployment revision, execution date, provider, input/output token count, latency, cost, sampling/reasoning settings, system-prompt hash, scenario-set hash, failures, and retry policy. Do not compare models when one received extra evidence or a different output contract.

