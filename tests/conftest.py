import re
import pytest
from app import create_app


@pytest.fixture()
def app(tmp_path):
    database = tmp_path / "test-cybernexus.db"
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-that-is-long-enough",
        "DATABASE_PATH": str(database),
        "BOOTSTRAP_ADMIN_PASSWORD": "TestAdminPass123",
        "INGEST_API_KEY": "test-ingest-key",
        "SESSION_COOKIE_SECURE": False,
    })
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf_from(response):
    html = response.get_data(as_text=True)
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "CSRF token was not rendered"
    return match.group(1)


def login_and_change_password(client):
    response = client.get("/login")
    token = csrf_from(response)
    response = client.post("/login", data={
        "csrf_token": token,
        "email": "admin@cybernexus.local",
        "password": "TestAdminPass123",
    })
    assert response.status_code == 302
    profile = client.get("/profile?required=1")
    token = csrf_from(profile)
    response = client.post("/profile", data={
        "csrf_token": token,
        "old_password": "TestAdminPass123",
        "new_password": "NewAdminPassword123",
        "confirm_password": "NewAdminPassword123",
    })
    assert response.status_code == 302
    return client.get("/")
