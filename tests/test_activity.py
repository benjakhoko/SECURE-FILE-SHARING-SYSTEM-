"""Activity log recording and visibility tests."""

from app.models import ActivityLog, File
from tests.helpers import login, upload_file


def _latest_file_id(app):
    with app.app_context():
        return File.query.order_by(File.id.desc()).first().id


def test_activity_logs_record_upload_download_and_login(app, client, make_user):
    make_user()
    login(client, "alice")
    upload_file(client, "audit.txt", b"audit me")
    file_id = _latest_file_id(app)
    client.get(f"/files/{file_id}/download")

    with app.app_context():
        actions = {log.action for log in ActivityLog.query.all()}
        assert {"login", "upload", "download"}.issubset(actions)

    response = client.get("/activity-logs")
    assert response.status_code == 200
    assert b"Uploaded and encrypted" in response.data
    assert b"Downloaded" in response.data


def test_activity_action_filter(app, client, make_user):
    make_user()
    login(client, "alice")
    upload_file(client, "filter.txt", b"filter")
    file_id = _latest_file_id(app)
    client.get(f"/files/{file_id}/download")

    response = client.get("/activity-logs?action=upload")
    assert response.status_code == 200
    assert b"filter.txt" in response.data
    # The upload record appears in the filtered table (plus once in the
    # notification dropdown); the download record must not be in the table.
    assert response.data.count(b"Downloaded &#39;filter.txt&#39;") == 1


def test_normal_user_only_sees_own_activity(app, client, make_user):
    make_user()
    make_user(username="bob", email="bob@example.com")

    bob_client = app.test_client()
    login(bob_client, "bob")
    upload_file(bob_client, "bob-secret.txt", b"bob data")

    login(client, "alice")
    response = client.get("/activity-logs")
    assert response.status_code == 200
    assert b"bob-secret.txt" not in response.data


def test_admin_sees_system_wide_activity(app, client, admin_id, make_user):
    make_user(username="bob", email="bob@example.com")
    bob_client = app.test_client()
    login(bob_client, "bob")
    upload_file(bob_client, "bob-secret.txt", b"bob data")

    login(client, "admin", password="AdminPass123")
    response = client.get("/activity-logs")
    assert response.status_code == 200
    assert b"bob-secret.txt" in response.data
    with app.app_context():
        assert ActivityLog.query.count() >= 3
