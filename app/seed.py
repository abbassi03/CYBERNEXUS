"""Idempotent demo-data loader. Run: python run.py seed-demo"""
from datetime import datetime, timedelta, timezone
from .db import get_db
from .security import utcnow
from .services.events import store_event


def seed_demo():
    db = get_db()
    if db.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"] > 0:
        print("Demo data already exists; leaving the database unchanged.")
        return
    assets = [
        ("Core API Gateway", "10.10.0.10", "network", "critical", "Infrastructure"),
        ("Customer Database", "10.10.1.20", "database", "critical", "Data Platform"),
        ("Finance Workstation 04", "10.10.2.44", "workstation", "high", "Finance"),
        ("Web Production Node", "10.10.0.30", "server", "high", "Engineering"),
        ("Analytics Worker", "10.10.3.15", "cloud", "medium", "Data Platform"),
        ("Internal Wiki", "10.10.4.12", "application", "low", "Operations"),
    ]
    for item in assets:
        db.execute("INSERT OR IGNORE INTO assets(name,ip_address,asset_type,criticality,owner,created_at) VALUES(?,?,?,?,?,?)", (*item, utcnow()))
    db.commit()
    asset_map = {r["name"]: r["id"] for r in db.execute("SELECT id,name FROM assets").fetchall()}
    now = datetime.now(timezone.utc).replace(microsecond=0)
    demo_events = [
        ("10.20.1.18", "10.10.0.10", "successful_login", "low", "Successful VPN authentication from managed endpoint.", "Core API Gateway"),
        ("10.20.1.25", "10.10.4.12", "firewall_block", "low", "Firewall blocked a connection to a restricted service.", "Internal Wiki"),
        ("198.51.100.23", "10.10.0.10", "port_scan", "medium", "Sequential connection attempts across exposed TCP ports.", "Core API Gateway"),
        ("203.0.113.77", "10.10.1.20", "malware_detected", "high", "Endpoint protection reported a quarantined test signature.", "Customer Database"),
        ("10.20.2.88", "10.10.3.15", "dns_anomaly", "medium", "Unusually long DNS query observed in lab telemetry.", "Analytics Worker"),
        ("192.0.2.55", "10.10.1.20", "data_exfiltration", "high", "Outbound transfer exceeded the configured demo threshold.", "Customer Database"),
        ("10.20.3.31", "10.10.2.44", "suspicious_process", "medium", "Unsigned process launched from a temporary directory.", "Finance Workstation 04"),
        ("10.20.1.19", "10.10.0.30", "successful_login", "low", "Successful administrator login using MFA.", "Web Production Node"),
        ("198.51.100.88", "10.10.0.10", "privilege_escalation", "high", "Unexpected privilege change detected in lab environment.", "Core API Gateway"),
    ]
    # Ten failures inside 14 minutes demonstrate escalation to a critical incident.
    for i in range(10):
        demo_events.append(("198.51.100.45", "10.10.0.10", "auth_failure", "medium", f"Failed authentication attempt {i + 1} in demo sequence.", "Core API Gateway"))
    auth_failure_index = 0
    for i, item in enumerate(demo_events):
        source_ip, destination_ip, event_type, severity, description, asset_name = item
        if event_type == "auth_failure":
            seconds_ago = 840 - auth_failure_index * 84
            auth_failure_index += 1
            event_time = (now - timedelta(seconds=seconds_ago)).isoformat()
        else:
            ago = (i % 7) * 24 + (i % 5) * 2
            event_time = (now - timedelta(hours=ago, minutes=i * 3)).isoformat()
        store_event({
            "event_time": event_time, "source_ip": source_ip, "destination_ip": destination_ip,
            "event_type": event_type, "severity": severity, "description": description,
            "source": "demo-telemetry", "asset_id": asset_map.get(asset_name),
        })
    print(f"Inserted {len(demo_events)} demo events and {len(assets)} assets.")
