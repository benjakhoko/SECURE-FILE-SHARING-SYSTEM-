"""Administrator authorization and account management tests."""

from app.extensions import db
from app.models import SecurityEvent, User
from tests.helpers import login


ADMIN_URLS = [
    "/admin/dashboard",
    "/admin/users",
    "/admin/files",
    "/admin/security",
]


def test_normal_user_cannot_access_administrator_pages(app, client, make_user):
    make_user()
    login(client, "alice")
    for url in ADMIN_URLS:
        assert client.get(url).status_code == 403

    with app.app_context():
        assert SecurityEvent.query.filter_by(
            event_type="unauthorized_access"
        ).count() >= len(ADMIN_URLS)


def test_administrator_can_access_admin_pages(app, client, admin_id):
    login(client, "admin", password="AdminPass123")
    for url in ADMIN_URLS:
        response = client.get(url)
        assert response.status_code == 200


def test_administrator_can_deactivate_and_reactivate_user(app, client, admin_id, make_user):
    bob_id = make_user(username="bob", email="bob@example.com")
    login(client, "admin", password="AdminPass123")

    response = client.post(f"/admin/users/{bob_id}/toggle", follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        assert db.session.get(User, bob_id).is_active is False
        assert SecurityEvent.query.filter_by(
            event_type="account_deactivated"
        ).count() == 1

    client.post(f"/admin/users/{bob_id}/toggle", follow_redirects=True)
    with app.app_context():
        assert db.session.get(User, bob_id).is_active is True
        assert SecurityEvent.query.filter_by(
            event_type="account_activated"
        ).count() == 1


def test_administrator_cannot_deactivate_self(app, client, admin_id):
    login(client, "admin", password="AdminPass123")
    response = client.post(f"/admin/users/{admin_id}/toggle", follow_redirects=True)
    assert b"cannot deactivate your own" in response.data
    with app.app_context():
        assert db.session.get(User, admin_id).is_active is True


def test_security_monitoring_shows_denied_admin_attempt(app, client, admin_id, make_user):
    make_user()
    login(client, "alice")
    client.get("/admin/dashboard")

    admin_client = app.test_client()
    login(admin_client, "admin", password="AdminPass123")
    response = admin_client.get("/admin/security")
    assert response.status_code == 200
    assert b"Non-administrator attempted to access an admin route" in response.data
