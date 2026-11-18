# Local operations runbook

## Start

```bash
source .venv/bin/activate
python run.py
```

## Seed sample telemetry

```bash
python run.py seed-demo
```

The seed command does not overwrite an existing event dataset. For a fresh dataset, stop the application, back up anything needed, and remove the local database file in `instance/` before running the seed command again.

## Stop

Press `Ctrl+C` in the terminal running Flask.

## Backup SQLite

Stop the application and copy `instance/cybernexus.db` to a protected backup location. Treat the database as sensitive security telemetry and restrict file permissions.

## Troubleshooting

- **Port 5000 is busy:** change the `port=5000` value in `run.py` and use the new local URL.
- **Login fails:** use the password configured before the first database initialization. A changed environment variable does not reset an existing account.
- **Demo account missing:** check that the database directory is writable. The bootstrap administrator is created when the database contains no users.
- **API returns 503:** set `CYBERNEXUS_INGEST_KEY` and restart the application.
- **CSV import rejects rows:** confirm UTF-8 encoding and all required headers. IP addresses must be valid IPv4 or IPv6 addresses, event types and severities must match the documented values, and descriptions are required.

## Security handling

Do not place real customer data or production security telemetry in the demo environment. Restrict access, protect backups, rotate secrets, and use HTTPS and a production database before any real-world pilot.
