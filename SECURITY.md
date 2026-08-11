# Security policy

This repository is a defensive research project. The default dataset is synthetic and the default tools are read-only.

- Do not submit customer telemetry, credentials, tokens, or production identifiers.
- The Defender connector accepts an access token at runtime and never persists it. Use the least-privileged `ThreatHunting.Read.All` permission.
- Human approval is required before containment or remediation. The project does not execute response actions.
- Report repository vulnerabilities through a private GitHub security advisory when available.

