# Agentic SOC Investigator

> **An autonomous, evidence-driven SOC investigation engine that turns an alert into hypotheses, defensive tool queries, evidence, MITRE ATT&CK context, confidence scores, and recommended next actions.**

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![FastAPI](https://img.shields.io/badge/API-FastAPI-green)
![Security](https://img.shields.io/badge/Mode-Defensive%20Simulation-purple)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Why this exists

Traditional alert pipelines frequently stop at detection. This project demonstrates the next layer: **structured investigation reasoning**.

Instead of returning only a severity score, the investigator asks:

1. What are the plausible explanations?
2. Which read-only security tools should be queried?
3. What evidence supports or contradicts each hypothesis?
4. Which ATT&CK techniques best explain the observed behavior?
5. How confident should an analyst be?
6. What safe remediation should be considered next?

## Architecture

```text
                       ┌──────────────────────────┐
                       │      Security Alert      │
                       └────────────┬─────────────┘
                                    │
                                    ▼
                       ┌──────────────────────────┐
                       │   Investigation Engine   │
                       │  Generate hypotheses     │
                       └────────────┬─────────────┘
                                    │
                   ┌────────────────┼─────────────────┐
                   ▼                ▼                 ▼
             ┌──────────┐     ┌──────────┐      ┌──────────┐
             │   SIEM   │     │ Identity │      │   EDR    │
             └────┬─────┘     └────┬─────┘      └────┬─────┘
                  │                │                 │
                  └────────────┬───┴─────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │ Evidence + TI lookup │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │ Hypothesis scoring   │
                    │ + ATT&CK mapping     │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │ Analyst-ready report │
                    └──────────────────────┘
```

## Demo investigation

The included synthetic scenario correlates:

- impossible travel
- MFA reset
- suspicious source-IP reputation
- large SharePoint download
- suspicious PowerShell execution
- credential-access endpoint signal

The engine compares three hypotheses:

- **Account takeover**
- **Endpoint compromise**
- **Benign travel / VPN**

and produces a deterministic evidence-backed confidence score for each.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:

- Demo UI: `http://localhost:8000`
- OpenAPI docs: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`

## Run with Docker

```bash
docker compose up --build
```

## API example

```bash
curl -X POST http://localhost:8000/investigate \
  -H 'Content-Type: application/json' \
  -d '{
    "alert_id":"ALRT-2026-001",
    "title":"Suspicious Entra sign-in followed by cloud download",
    "severity":"high",
    "user":"maya.chen@contoso.example",
    "device":"FIN-LT-044",
    "src_ip":"203.0.113.66",
    "timestamp":"2026-08-09T10:34:00Z",
    "description":"Impossible travel and unusual data access were observed."
  }'
```

## Example output shape

```json
{
  "verdict": "confirmed_compromise",
  "risk_score": 92,
  "hypotheses": [
    {
      "name": "Account takeover",
      "confidence": 0.98,
      "status": "supported"
    }
  ],
  "mitre_attack": [
    {"technique_id": "T1078", "name": "Valid Accounts"}
  ],
  "recommended_actions": [
    "Revoke active sessions and refresh tokens for the affected identity."
  ]
}
```

## Design principles

- **Evidence before conclusions** — every hypothesis exposes the observations that changed its confidence.
- **Read-only tools by default** — tool interfaces query synthetic telemetry only.
- **Human approval for consequential actions** — the engine recommends; it does not execute containment.
- **Deterministic MVP** — no API key or external LLM is required to run the demo.
- **Replaceable reasoning layer** — the deterministic scorer can later be augmented by an LLM planner/evaluator while retaining evidence controls.

## Roadmap

### v0.2
- Temporal evidence graph
- Richer ATT&CK tactic/technique chain visualization
- Analyst feedback loop
- Investigation-memory retrieval
- Pluggable tool registry

### v0.3
- Safe connectors for Sentinel / Defender / Entra-style APIs
- RAG over prior synthetic incident reports
- LLM planner with structured tool calls and explicit allowlists
- Evaluation harness for hallucination, unsupported conclusions, and tool-selection accuracy

### v1.0 vision
A production-oriented investigation platform where AI agents can plan multi-step investigations across SIEM, identity, endpoint, cloud, and threat-intelligence systems while preserving evidence provenance, least privilege, observability, and human control.

## Safety

This project intentionally contains **synthetic telemetry and defensive investigation logic only**. It is not a penetration-testing framework and does not perform exploitation, persistence, credential collection, or unauthorized system interaction.

## License

MIT
