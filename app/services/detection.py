"""Explainable defensive detection rules and lightweight anomaly scoring.

This is a transparent rule/statistical baseline, not a trained ML model. It is
intended for demos and triage; production deployments should calibrate it to
an organization's network and telemetry.
"""
from datetime import datetime, timedelta, timezone

SEVERITIES = {"low": 15, "medium": 35, "high": 65, "critical": 85}
VALID_SEVERITIES = set(SEVERITIES)
VALID_EVENT_TYPES = {
    "auth_failure", "successful_login", "port_scan", "malware_detected",
    "suspicious_process", "firewall_block", "data_exfiltration", "dns_anomaly",
    "privilege_escalation", "policy_violation", "other",
}


def assess_event(db, source_ip, event_type, severity, event_time):
    """Return (severity, score, reason, anomalous) after explainable checks."""
    severity = severity.lower().strip()
    event_type = event_type.lower().strip()
    if severity not in VALID_SEVERITIES:
        severity = "medium"
    reasons = []
    score = SEVERITIES[severity]

    if event_type in {"malware_detected", "data_exfiltration", "privilege_escalation"}:
        severity = "critical"
        score = max(score, 90)
        reasons.append({
            "malware_detected": "Malware detection requires immediate triage.",
            "data_exfiltration": "Potential data-exfiltration activity requires immediate triage.",
            "privilege_escalation": "Potential privilege escalation requires immediate triage.",
        }[event_type])
    elif event_type == "port_scan":
        severity = "high" if severity in {"low", "medium"} else severity
        score = max(score, 70)
        reasons.append("Port-scan activity observed; validate source and destination scope.")
    elif event_type == "suspicious_process":
        severity = "high" if severity in {"low", "medium"} else severity
        score = max(score, 72)
        reasons.append("Suspicious process activity requires analyst review.")
    elif event_type == "dns_anomaly":
        score = max(score, 55)
        reasons.append("Unusual DNS activity flagged for review.")

    if event_type == "auth_failure" and source_ip:
        try:
            point = datetime.fromisoformat(event_time)
            if point.tzinfo is None:
                point = point.replace(tzinfo=timezone.utc)
            cutoff = (point - timedelta(minutes=15)).isoformat()
        except ValueError:
            cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
        row = db.execute(
            "SELECT COUNT(*) AS n FROM events WHERE source_ip=? AND event_type='auth_failure' AND event_time>=? AND event_time<=?",
            (source_ip, cutoff, event_time),
        ).fetchone()
        failures = int(row["n"] or 0) + 1
        if failures >= 5:
            severity = "critical" if failures >= 10 else "high"
            score = max(score, 90 if failures >= 10 else 78)
            reasons.append(f"Repeated authentication failures: {failures} from this source in 15 minutes.")

    score = min(100, int(score))
    anomalous = score >= 70 or bool(reasons)
    return severity, score, " ".join(reasons) if reasons else "No detection rule matched; baseline severity retained.", anomalous
