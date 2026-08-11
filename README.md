# Agentic SOC Investigator

An evidence-first applied AI security research platform for investigating identity, endpoint, cloud, and OAuth attacks. It turns normalized telemetry into auditable findings: each verdict links to supporting events, competing hypotheses, an entity-event graph, MITRE ATT&CK techniques, and human-approved response recommendations.

The repository is designed as a portfolio-scale research artifact for Microsoft Defender Experts–style work. It combines a runnable investigation engine, repeatable experiments, defensive KQL, a read-only Microsoft Defender connector, an analyst UI, and a candid research report.

> **Research boundary:** all checked-in telemetry is synthetic. The offline results are regression-test evidence, not a production effectiveness claim. No autonomous containment actions are implemented.

## What is included

- Four reproducible cases: three multi-stage attacks and one ambiguous benign VPN/travel control.
- Evidence-grounded investigations with risk scoring, citations, hypothesis ranking, and ATT&CK mapping.
- An entity-event-technique graph that exposes relationships hidden across individual alerts.
- A shared evaluation contract for verdicts, attack recall, benign specificity, hypotheses, ATT&CK quality, and citation quality.
- Evidence-first, alert-only, and permissive keyword ablations, plus replay support for real-model JSONL outputs.
- Defensive Advanced Hunting queries for identity takeover, endpoint lateral movement, and OAuth consent abuse.
- A minimal read-only Microsoft Graph connector for Defender Advanced Hunting.
- FastAPI endpoints and a compact analyst workbench.

## Architecture

```text
synthetic telemetry / Defender hunting results
                    |
                    v
          normalized security events
                    |
        +-----------+------------+
        |                        |
 behavioral features      entity-event graph
        |                        |
        +-----------+------------+
                    v
          competing hypotheses
                    |
                    v
 evidence-grounded verdict + ATT&CK + analyst actions
                    |
                    v
          shared evaluation contract
```

See [docs/architecture.md](docs/architecture.md) for design details and trust boundaries.

## Quick start

The core investigation and evaluation paths use only the Python standard library. Python 3.11 or later is recommended.

```bash
python scripts/run_scenarios.py
python scripts/compare_models.py
python -m unittest discover -s tests -v
```

The current checked-in fixture results are:

| System | Verdict accuracy | Attack recall | Benign specificity | Hypothesis accuracy | Evidence coverage |
|---|---:|---:|---:|---:|---:|
| Evidence-first v0.2 | 100% | 100% | 100% | 100% | 100% |
| Alert-only ablation | 75% | 100% | 0% | 50% | 0% |
| Permissive keyword baseline | 75% | 100% | 0% | 25% | 0% |

Read [docs/research-report.md](docs/research-report.md) before interpreting those numbers. The four fixtures are intentionally small and synthetic.

## Run the analyst workbench

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`. The API exposes:

- `GET /health`
- `GET /api/scenarios`
- `POST /api/investigate/{scenario_id}`
- `GET /api/evaluation`

Docker is also supported:

```bash
docker compose up --build
```

## Compare actual AI models

Export an identical, versioned prompt bundle for external model runners:

```bash
python scripts/export_model_prompts.py --output /tmp/soc-prompts.jsonl
```

Replay one or more model outputs through the same scoring contract:

```bash
python scripts/compare_models.py \
  --prediction model-a=/path/to/model-a.jsonl \
  --prediction model-b=/path/to/model-b.jsonl
```

Prediction files use one JSON object per scenario:

```json
{"scenario_id":"identity-takeover-cloud-exfiltration","verdict":"confirmed_compromise","primary_hypothesis":"Account takeover and cloud data theft","technique_ids":["T1078","T1098","T1530"],"evidence_event_ids":["evt-id-001","evt-id-002"]}
```

The repository deliberately does not claim results for models that have not been run. The full protocol, including repeated stochastic trials and cost/latency reporting, is in [docs/experiment-design.md](docs/experiment-design.md).

## Microsoft Defender integration

The connector calls the Microsoft Graph `security/runHuntingQuery` endpoint and requires a runtime token with `ThreatHunting.Read.All`. Tokens are neither logged nor persisted.

```python
from app.connectors.defender_graph import DefenderGraphConnector

connector = DefenderGraphConnector.from_environment()
result = connector.run_hunting_query("DeviceProcessEvents | take 10", timespan="P7D")
```

Set `DEFENDER_GRAPH_ACCESS_TOKEN` only in the runtime environment. Use a test tenant, least privilege, and your organization's authorization process. See [detections/README.md](detections/README.md) for the current table assumptions and defensive queries.

## Cases

| Case | Key evidence | Expected result |
|---|---|---|
| Identity takeover and cloud exfiltration | unfamiliar sign-in, MFA change, high-volume download | Confirmed compromise; T1078, T1098, T1530 |
| Endpoint lateral movement | encoded PowerShell, credential dumping, remote service logon | Confirmed compromise; T1059.001, T1003.001, T1021.002, T1071.001 |
| OAuth application abuse | risky consent, mailbox access, cloud-file collection | Confirmed compromise; T1098.003, T1078.004, T1114.002, T1530 |
| Authorized VPN/travel | known egress, approved travel, compliant device, normal usage | Benign; no ATT&CK mapping |

## Repository map

```text
app/                  investigation, graph, evaluation, API, connector, UI
data/scenarios/       versioned synthetic telemetry and ground truth
detections/kql/       Microsoft Defender Advanced Hunting queries
docs/                 architecture, experiment design, provenance, report
reports/              reproducible offline metrics snapshot
scripts/              scenario runner, prompt exporter, model comparison
tests/                unit, fixture, KQL, connector, and evaluation checks
```

## Safety and responsible use

- Keep collection and hunting read-only unless a human authorizes a separate response workflow.
- Treat telemetry as untrusted input; do not allow event text to override system or analyst instructions.
- Do not commit tenant data, access tokens, secrets, or personal information.
- Require an analyst to approve containment, account disablement, token revocation, or device isolation.
- Revalidate KQL schemas in the target tenant before operational use.

See [SECURITY.md](SECURITY.md) for reporting and operational safeguards, and [docs/data-provenance.md](docs/data-provenance.md) for fixture provenance.

## Documentation

- [Architecture and threat model](docs/architecture.md)
- [Experiment design](docs/experiment-design.md)
- [Model comparison guide](docs/model-comparison.md)
- [Data provenance](docs/data-provenance.md)
- [Offline research report](docs/research-report.md)
- [KQL schema notes](detections/README.md)

Contributions are welcome under [CONTRIBUTING.md](CONTRIBUTING.md). This project is licensed under the [MIT License](LICENSE).
