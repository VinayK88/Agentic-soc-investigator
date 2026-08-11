# Evidence-first AI-assisted SOC investigation: offline study

## Executive finding

On the four checked-in fixtures, the evidence-first pipeline preserved 100% attack recall while correctly closing the negative control and citing all expected supporting events. The two alert-text baselines also recalled all three attacks, but both failed the benign control and cited no supporting telemetry. This demonstrates the intended behavior of the implementation; it does not establish real-world effectiveness because the cases are synthetic and were authored with the system.

## Method

Three attack cases and one deliberately ambiguous benign control were evaluated with one scoring contract. The evidence-first system used normalized telemetry, behavioral features, threat-intelligence context, an entity-event graph, competing hypotheses, and deterministic ATT&CK mapping. The ablations used only alert text or a permissive escalation rule.

Run the study with:

```bash
python scripts/compare_models.py
```

## Results

| System | Verdict accuracy | Attack recall | Benign specificity | Hypothesis accuracy | Technique precision | Technique recall | Citation precision | Evidence coverage |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Evidence-first v0.2 | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| Alert-only ablation | 75% | 100% | 0% | 50% | 60% | 27% | 0% | 0% |
| Permissive keyword baseline | 75% | 100% | 0% | 25% | 38% | 27% | 0% | 0% |

Both alert-text baselines looked acceptable if judged only by attack recall. Adding benign specificity, hypothesis accuracy, ATT&CK quality, and evidence coverage exposed their weaknesses. This is operationally important because an investigator that escalates everything can have high recall while increasing analyst workload and providing little basis for action.

## Case outcomes

- Identity takeover: risk 90/100; account takeover and cloud data theft; T1078, T1098, T1530.
- Endpoint lateral movement: risk 76/100; endpoint compromise and lateral movement; T1059.001, T1003.001, T1021.002, T1071.001.
- OAuth abuse: risk 90/100; OAuth application abuse; T1098.003, T1078.004, T1114.002, T1530.
- Benign VPN control: risk 14/100; authorized travel/corporate VPN; no ATT&CK mapping.

## Limitations

The sample size is four; cases are synthetic; the evidence-first rules and labels were developed together; thresholds are uncalibrated; and no analyst inter-rater agreement, production telemetry, model cost, or repeated stochastic LLM trials are included. The perfect evidence-first score must therefore be read as a regression-test result.

## Next experiment

Use the exported prompt bundle to compare at least three immutable model versions, run each case repeatedly, and report metric distributions, latency, token cost, unsupported citations, and refusal/tool-selection failures. Expand the evaluation set with blind cases, missing evidence, adversarial instructions embedded in telemetry, false-positive-heavy benign traffic, and independently reviewed public or authorized data.

