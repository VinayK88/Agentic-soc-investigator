# Data provenance

## Checked-in fixtures

All events in `data/scenarios/` are synthetic. IP addresses use documentation ranges, identities use the reserved `contoso.example` domain, payloads are redacted placeholders, and no customer or production data is included.

The cases are inspired by widely documented defensive patterns and mapped to MITRE ATT&CK technique identifiers. The repository does not claim that the fixtures reproduce any specific real victim, actor, or Microsoft customer incident.

## External data

The architecture can be extended with properly licensed public datasets such as OTRF Security Datasets or telemetry generated in an authorized lab with Atomic Red Team. External data is not vendored here because provenance, license, schema, and dataset-version checks must be explicit.

For every imported dataset, record:

- canonical source URL and immutable revision/hash
- license and redistribution terms
- collection environment and sensor coverage
- benign/malicious labeling method
- ATT&CK mappings and reviewer
- transformations, filters, exclusions, and class balance
- known leakage between training and evaluation cases

## Authorized enterprise data

`DefenderGraphConnector` can run read-only KQL through Microsoft Graph when the caller provides an authorized token. Do not commit query results. De-identify and obtain approval before using enterprise events in a public portfolio or model-evaluation artifact.

