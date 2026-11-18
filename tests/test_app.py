import sqlite3
from .conftest import csrf_from, login_and_change_password


def test_health_endpoint(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_unauthenticated_dashboard_redirects_to_login(client):
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_requires_csrf(client):
    response = client.post("/login", data={"email": "admin@cybernexus.local", "password": "x"})
    assert response.status_code == 400


def test_bootstrap_password_change_and_dashboard(app, client):
    response = login_and_change_password(client)
    assert response.status_code == 200
    assert b"Security overview" in response.data
    with app.app_context():
        db = sqlite3.connect(app.config["DATABASE_PATH"])
        row = db.execute("SELECT must_change_password FROM users WHERE email=?", ("admin@cybernexus.local",)).fetchone()
        db.close()
    assert row == (0,)


def test_port_scan_is_scored_and_malware_escalates(app, client):
    login_and_change_password(client)
    response = client.get("/events/")
    token = csrf_from(response)
    response = client.post("/events/new", data={
        "csrf_token": token,
        "source_ip": "198.51.100.23",
        "destination_ip": "10.10.0.10",
        "event_type": "port_scan",
        "severity": "medium",
        "description": "Repeated connections to multiple ports in test network.",
        "source": "pytest",
    })
    assert response.status_code == 302
    response = client.get("/events/")
    token = csrf_from(response)
    response = client.post("/events/new", data={
        "csrf_token": token,
        "source_ip": "203.0.113.44",
        "destination_ip": "10.10.1.20",
        "event_type": "malware_detected",
        "severity": "medium",
        "description": "Test malware alert from a simulated endpoint.",
        "source": "pytest",
    })
    assert response.status_code == 302
    with app.app_context():
        db = sqlite3.connect(app.config["DATABASE_PATH"])
        event = db.execute("SELECT severity,risk_score,is_anomalous FROM events WHERE source_ip=?", ("198.51.100.23",)).fetchone()
        incident_count = db.execute("SELECT COUNT(*) FROM incidents WHERE event_id IN (SELECT id FROM events WHERE source_ip=?)", ("203.0.113.44",)).fetchone()[0]
        db.close()
    assert event[0] == "high"
    assert event[1] >= 70
    assert event[2] == 1
    assert incident_count == 1


def test_api_ingestion_requires_key(app, client):
    payload = {
        "source_ip": "192.0.2.20", "event_type": "dns_anomaly", "severity": "medium",
        "description": "Synthetic DNS anomaly from API test.",
    }
    denied = client.post("/api/v1/events", json=payload)
    assert denied.status_code == 401
    accepted = client.post("/api/v1/events", json=payload, headers={"X-API-Key": "test-ingest-key"})
    assert accepted.status_code == 201
    assert accepted.get_json()["is_anomalous"] is False or accepted.get_json()["risk_score"] >= 55


def test_login_throttle_returns_429(client):
    response = client.get("/login")
    token = csrf_from(response)
    for _ in range(5):
        response = client.post("/login", data={
            "csrf_token": token,
            "email": "admin@cybernexus.local",
            "password": "incorrect-password",
        })
        assert response.status_code == 200
    blocked = client.post("/login", data={
        "csrf_token": token,
        "email": "admin@cybernexus.local",
        "password": "TestAdminPass123",
    })
    assert blocked.status_code == 429
