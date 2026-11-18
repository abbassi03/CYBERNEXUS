# CYBERNEXUS

**Defensive Security Operations Center (SOC) demo platform** built with Python and Flask. CYBERNEXUS brings security-event triage, explainable detection rules, incident response, asset inventory, reporting, and controlled API ingestion into one local web application.

> **Project status:** portfolio/demo release. It is a functional starting point for learning and demonstration, not a certified SIEM, EDR, or production security platform. Detection rules are intentionally transparent heuristics and require environment-specific tuning before operational use.

## Features

- **Security overview:** event and incident counters, seven-day activity chart, severity distribution, recent signals, and incident queue.
- **Event management:** manual event entry, filtering, event detail, analyst status workflow, and CSV import/export.
- **Explainable detection:** rule-based risk scoring for malware, possible exfiltration, privilege escalation, port scans, suspicious processes, DNS anomalies, and repeated authentication failures.
- **Incident response:** critical detections automatically create linked incidents; analysts can set priority, status, and assignee.
- **Asset inventory:** register servers, workstations, network devices, cloud assets, databases, and applications with criticality and ownership.
- **Users and roles:** administrator, analyst, and read-only viewer roles; bootstrap administrator must change the temporary password on first sign-in.
- **Audit trail:** records authentication and analyst/admin changes.
- **API ingestion:** optional machine-to-machine event endpoint protected by a dedicated API key.
- **Security foundations:** password hashing, CSRF protection for browser mutations, parameterized SQL, role checks, input validation, security response headers, and file-size/CSV row limits. Sign-in attempts are throttled after five failed attempts per email/IP pair within 15 minutes.
- **Deployment options:** local Flask run mode and Docker/Gunicorn configuration.

## Technology stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+ / Flask |
| Database | SQLite (local demo) |
| UI | Jinja templates, HTML, custom CSS, vanilla JavaScript |
| Authentication | Flask sessions + Werkzeug password hashing |
| Detection | Explainable Python rules and correlation |
| API | JSON REST endpoint with API-key authentication |
| Deployment | Gunicorn + Docker Compose |
| Tests | pytest + Flask test client |

## Quick start on Kali Linux / Debian / Ubuntu

```bash
# 1. Enter the project directory
cd CYBERNEXUS

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install the dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4. (Recommended) Set a private secret and an initial admin password
export CYBERNEXUS_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export CYBERNEXUS_ADMIN_PASSWORD='Choose-A-Unique-Temp-Password-123'

# 5. Load sample assets, events, and incidents
python run.py seed-demo

# 6. Start the local server
python run.py
```

Open **http://127.0.0.1:5000** in your browser.

### First-run sign-in

- Email: `admin@cybernexus.local`
- Password: the value you set in `CYBERNEXUS_ADMIN_PASSWORD`.
- If no environment variable was set before the database was first created, the local-demo fallback password is `CyberNexus@2026`.

The bootstrap administrator is forced to change the temporary password at first sign-in. The bootstrap user is only created when the database has no users. If you already created the database, changing the environment variable will not reset the existing user's password; use the profile page instead.

### Load demo data later

```bash
source .venv/bin/activate
python run.py seed-demo
```

The loader is idempotent: it will not duplicate the main demo event set if events already exist.

## Run tests

```bash
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

## Optional event-ingestion API

The API endpoint is disabled until a dedicated key is configured:

```bash
export CYBERNEXUS_INGEST_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(40))')"
python run.py
```

Health check:

```bash
curl http://127.0.0.1:5000/api/v1/health
```

Ingest an event (replace the API key):

```bash
curl -X POST http://127.0.0.1:5000/api/v1/events \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: YOUR_INGEST_KEY' \
  -d '{"source_ip":"198.51.100.23","destination_ip":"10.10.0.10","event_type":"port_scan","severity":"medium","description":"Sequential TCP connection attempts","source":"edge-firewall"}'
```

See [docs/API.md](docs/API.md) for the full payload and response behavior.

## Docker deployment

1. Copy `.env.example` to `.env`.
2. Set strong random values for `CYBERNEXUS_SECRET_KEY` and `CYBERNEXUS_ADMIN_PASSWORD`. Optionally set `CYBERNEXUS_INGEST_KEY`.
3. Start the service:

```bash
docker compose up --build -d
```

The compose file binds to `127.0.0.1:8000` by default and persists SQLite data in a named volume. Put a TLS-terminating reverse proxy in front before exposing it to a network. Set `CYBERNEXUS_COOKIE_SECURE=1` only when the app is accessed through HTTPS.

## Repository structure

```text
CYBERNEXUS/
├── app/
│   ├── api/                  # API health and event ingestion
│   ├── assets/               # Asset inventory routes
│   ├── audit/                # Administrator audit trail
│   ├── auth/                 # Login, profile, roles, team management
│   ├── dashboard/            # SOC overview
│   ├── events/               # Event search, entry, CSV import
│   ├── incidents/            # Incident lifecycle workflow
│   ├── reports/              # Analytics and CSV export
│   ├── services/             # Event normalization and detection engine
│   ├── static/               # CSS, JavaScript, sample CSV
│   ├── templates/            # Jinja UI templates
│   ├── db.py                 # SQLite schema and connection helpers
│   └── security.py           # Auth helpers, CSRF, audit logging
├── docs/                     # Architecture, data model, API, operations, detection rules
├── instance/                 # Local SQLite database (ignored by Git)
├── tests/                    # Automated application tests
├── config.py
├── run.py                    # Local development entry point
├── wsgi.py                   # Gunicorn WSGI entry point
├── Dockerfile
├── compose.yaml
├── requirements.txt
└── README.md
```

## Roles

| Role | Permissions |
|---|---|
| Administrator | Full workspace access, user management, audit trail |
| Analyst | Review events, create/update incidents, manage assets |
| Viewer | Read-only access to dashboards and records |

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Data model](docs/DATA-MODEL.md)
- [Detection rules](docs/DETECTION-RULES.md)
- [API reference](docs/API.md)
- [Local operations runbook](docs/OPERATIONS.md)

## Detection behavior

The detection layer uses clear, reviewable heuristics and correlation windows. For example, five failed authentication attempts from the same source within 15 minutes raise the event to high severity; ten or more raise it to critical. Malware, potential exfiltration, and privilege-escalation signals are escalated to critical and create an incident. Full details and caveats are in [docs/DETECTION-RULES.md](docs/DETECTION-RULES.md).

## Security and production-readiness notes

Before using this outside a local demo:

1. Set a strong `CYBERNEXUS_SECRET_KEY`, bootstrap password, and separate API key. Do not commit `.env` or database files.
2. Deploy behind HTTPS; enable secure cookies; restrict access to trusted analysts and ingestion collectors.
3. Replace SQLite with PostgreSQL for concurrent or multi-instance workloads, and introduce versioned database migrations and tested backups.
4. Add proper authentication rate limiting, centralized secrets management, structured logging, monitoring, and a documented incident response process.
5. Calibrate detection thresholds against representative telemetry, measure false positives/negatives, and add source-specific parsers and enrichment.
6. Perform an independent security review and penetration test before production use.

The app does not scan external targets, execute uploaded content, or take automated containment actions. It is designed for defensive event triage and incident tracking.

## License

MIT. See [LICENSE](LICENSE).
