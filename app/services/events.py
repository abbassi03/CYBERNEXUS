"""Event validation, normalization, storage, and incident escalation."""
import ipaddress
from datetime import datetime, timezone
from .detection import VALID_EVENT_TYPES, VALID_SEVERITIES, assess_event
from ..security import utcnow
from ..db import get_db


def validate_ip(value, required=False):
    value = (value or "").strip()
    if not value and not required:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value}") from exc


def normalize_event(data):
    source_ip = validate_ip(data.get("source_ip"), required=True)
    destination_ip = validate_ip(data.get("destination_ip", ""))
    event_type = str(data.get("event_type", "other")).strip().lower()
    severity = str(data.get("severity", "medium")).strip().lower()
    if event_type not in VALID_EVENT_TYPES:
        raise ValueError("Unsupported event type.")
    if severity not in VALID_SEVERITIES:
        raise ValueError("Severity must be low, medium, high, or critical.")
    description = str(data.get("description", "")).strip()
    if not description or len(description) > 1000:
        raise ValueError("Description is required and must be 1000 characters or fewer.")
    source = str(data.get("source", "manual")).strip()[:80] or "manual"
    asset_id = data.get("asset_id") or None
    if asset_id not in (None, ""):
        try:
            asset_id = int(asset_id)
        except (TypeError, ValueError):
            raise ValueError("Asset ID must be a number.")
    else:
        asset_id = None
    event_time = str(data.get("event_time") or utcnow()).strip()
    try:
        parsed = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        event_time = parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    except ValueError as exc:
        raise ValueError("Event time must be an ISO 8601 timestamp.") from exc
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "event_type": event_type,
        "severity": severity,
        "description": description,
        "source": source,
        "asset_id": asset_id,
        "event_time": event_time,
    }


def store_event(data):
    db = get_db()
    event = normalize_event(data)
    if event["asset_id"]:
        asset = db.execute("SELECT id FROM assets WHERE id=?", (event["asset_id"],)).fetchone()
        if not asset:
            raise ValueError("Selected asset does not exist.")
    severity, score, reason, anomalous = assess_event(
        db, event["source_ip"], event["event_type"], event["severity"], event["event_time"]
    )
    cur = db.execute(
        """INSERT INTO events(event_time,source_ip,destination_ip,event_type,severity,description,source,
           asset_id,risk_score,detection_reason,is_anomalous,created_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (event["event_time"], event["source_ip"], event["destination_ip"], event["event_type"],
         severity, event["description"], event["source"], event["asset_id"], score, reason,
         int(anomalous), utcnow()),
    )
    event_id = cur.lastrowid
    # Critical findings are escalated into incidents; duplicates are avoided.
    if severity == "critical":
        existing = db.execute("SELECT id FROM incidents WHERE event_id=?", (event_id,)).fetchone()
        if not existing:
            title = f"{event['event_type'].replace('_', ' ').title()} from {event['source_ip']}"
            db.execute(
                """INSERT INTO incidents(title,description,severity,priority,status,event_id,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (title, reason + " " + event["description"], severity, "critical", "open", event_id, utcnow(), utcnow()),
            )
    db.commit()
    return db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
