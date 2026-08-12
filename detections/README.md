# Defender XDR hunting content

These queries target the Microsoft Defender XDR advanced-hunting schema current in August 2026. They use `EntraIdSignInEvents`, `CloudAppEvents`, `DeviceProcessEvents`, and `DeviceLogonEvents`.

Important operational notes:

- `EntraIdSignInEvents` requires the applicable Microsoft Entra licensing and is replacing the legacy `AADSignInEventsBeta` name. Check schema availability in the target tenant before deployment.
- `CloudAppEvents` depends on Microsoft Defender for Cloud Apps data and connected cloud applications.
- `ActionType` values can vary by workload. Validate them with the Defender portal's built-in schema reference.
- Thresholds are research defaults, not production recommendations. Tune them against a benign baseline and record resulting alert volume and precision.
- The repository includes a read-only Microsoft Graph connector for `POST /v1.0/security/runHuntingQuery`; the least-privileged permission documented by Microsoft is `ThreatHunting.Read.All`.

Primary references:

- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table
- https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0

