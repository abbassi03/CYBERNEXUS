# Architecture

CYBERNEXUS is a modular Flask application with server-rendered Jinja templates and a SQLite persistence layer.

```text
Browser
  │ HTTPS (recommended outside local development)
  ▼
Flask application factory (app/__init__.py)
  ├── Authentication / authorization / CSRF
  ├── Dashboard and reporting blueprints
  ├── Events blueprint ──► event validation ──► detection rules
  ├── Incidents blueprint
  ├── Asset inventory blueprint
  └── API ingestion blueprint (separate API key)
            │
            ▼
       SQLite database
       ├── users
       ├── assets
       ├── events
       ├── incidents
       └── audit_logs
```

## Design decisions

- Application factory enables isolated test databases and deployment configuration.
- Blueprints separate authentication, dashboard, telemetry, incident response, assets, reports, and API ingestion.
- SQLite is suitable for a local demo and a single-node evaluation environment. Use PostgreSQL and a managed migration workflow before multi-instance production use.
- SQL queries are parameterized. Foreign keys and indexes are enabled.
- Passwords are stored as Werkzeug password hashes; clear-text passwords are never stored in the database.
- Browser write operations require session-bound CSRF tokens. The machine-to-machine ingestion endpoint uses a separate API key.
- The initial administrator must change the temporary password at first sign-in.
- Security events are immutable observations from ingestion; analyst workflow status is stored separately on the event record.
- Critical detections create linked incident records automatically.

## Trust boundaries

The application does not execute uploaded files, scan third-party systems, or perform active network actions. CSV import accepts structured event records only. The event-ingestion API should only be reachable by trusted telemetry collectors over TLS.
