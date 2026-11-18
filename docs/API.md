# Event ingestion API

The API is intentionally small. The ingestion endpoint is disabled unless `CYBERNEXUS_INGEST_KEY` is configured.

## Health

`GET /api/v1/health`

Returns service name, status, timestamp, and version. It does not expose database or host details.

## Ingest an event

`POST /api/v1/events`

Headers:

```http
Content-Type: application/json
X-API-Key: <CYBERNEXUS_INGEST_KEY>
```

Example body:

```json
{
  "event_time": "2026-11-18T13:30:00+00:00",
  "source_ip": "198.51.100.23",
  "destination_ip": "10.10.0.10",
  "event_type": "port_scan",
  "severity": "medium",
  "description": "Sequential connections across multiple TCP ports",
  "source": "edge-firewall",
  "asset_id": 1
}
```

Supported event types: `auth_failure`, `successful_login`, `port_scan`, `malware_detected`, `suspicious_process`, `firewall_block`, `data_exfiltration`, `dns_anomaly`, `privilege_escalation`, `policy_violation`, `other`.

Successful ingestion returns HTTP 201 with event ID, assessed severity, risk score, anomaly flag, and detection explanation. Invalid fields return HTTP 400; missing/invalid API keys return HTTP 401. If the key is not configured, the route returns HTTP 503.
