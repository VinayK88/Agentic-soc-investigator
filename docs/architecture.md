# Architecture

## Objective

The platform separates deterministic evidence handling from probabilistic model reasoning. An LLM may propose a hypothesis or summarize a case, but event retrieval, citation validation, ATT&CK mapping, scoring, and action authorization remain explicit and testable.

```text
Synthetic cases or authorized Defender XDR query results
                         |
                         v
               Normalized security events
                         |
             +-----------+-----------+
             |                       |
             v                       v
     Behavioral features       Evidence graph
             |                       |
             +-----------+-----------+
                         v
                Hypothesis evaluation
                         |
              +----------+-----------+
              |                      |
              v                      v
      Evidence-backed report    ATT&CK mapping
              |                      |
              +----------+-----------+
                         v
              Model-agnostic evaluation
```

## Components

- `app/scenarios.py` loads reproducible attack and negative-control cases.
- `app/tools.py` exposes read-only identity, endpoint, cloud, and network queries over a scenario.
- `app/analytics.py` calculates transparent behavioral features and a bounded anomaly score.
- `app/graph.py` constructs entity-event-technique paths without requiring a graph database.
- `app/engine.py` evaluates competing hypotheses and emits an evidence-cited report.
- `app/evaluation.py` scores deterministic baselines and replayed real-model outputs with the same contract.
- `app/connectors/defender_graph.py` provides an optional read-only Microsoft Graph advanced-hunting client.
- `detections/kql/` contains current-schema Defender XDR hunting queries.

## Security boundaries

1. The default runtime uses synthetic data and no credentials.
2. The Defender connector accepts a token only at runtime and exposes only the advanced-hunting action.
3. Model outputs are treated as untrusted predictions and rescored against known event IDs.
4. Remediation is recommendation-only. Consequential actions require human approval outside this application.
5. The evaluation dataset is separate from exported prompts' ground truth.

## Production evolution

A production implementation would add tenant isolation, encrypted secret storage, schema/version registries, an append-only evidence store, OpenTelemetry traces, workload identity, rate limits, case-level authorization, streaming ingestion, and an analyst feedback loop. Those are deliberately documented but not simulated as if they already exist.

