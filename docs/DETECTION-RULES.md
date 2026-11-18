# Detection model

The included detection engine is an explainable local baseline, not a trained machine-learning model and not a replacement for a commercial SIEM.

| Signal | Rule | Default result |
|---|---|---|
| `malware_detected` | Endpoint malware alert | Critical; create incident |
| `data_exfiltration` | Potential data transfer anomaly | Critical; create incident |
| `privilege_escalation` | Unexpected privilege change | Critical; create incident |
| `port_scan` | Port-scan telemetry | At least high |
| `suspicious_process` | Suspicious process telemetry | At least high |
| `dns_anomaly` | Unusual DNS telemetry | Risk score at least 55 |
| `auth_failure` | Five or more failures from one source within 15 minutes | High; ten or more is critical |

## Risk scores

Base values are low=15, medium=35, high=65, critical=85. Rule-specific checks raise the score, capped at 100. Scores are triage hints and must be calibrated against real baseline traffic and false-positive rates before operational use.

## Operational guidance

1. Validate the source, destination, timestamps, asset context, and raw evidence.
2. Confirm the alert with endpoint, identity, network, and cloud telemetry where relevant.
3. Record an incident, assign an owner, and document containment and recovery steps.
4. Mark false positives only after recording the reason in the incident/audit process.
