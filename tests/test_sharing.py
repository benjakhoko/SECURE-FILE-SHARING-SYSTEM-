"""Sharing rules and permission management tests."""

from app.extensions import db
from app.models import File, FilePermission
from tests.helpers import login, share_file, upload_file


def _latest_file_id(app):
    with app.app_context():
        return File.query.order_by(File.id.desc()).first().id


def _permission_count(app):
    with app.app_context():
        return FilePermission.query.count()


def test_user_cannot_share_file_they_do_not_own(app, client, make_user):
    make_user()
    make_user(username="bob", email="bob@example.com")
    make_user(username="charlie", email="charlie@example.com")
    login(client, "alice")
    upload_file(client, "owned-by-alice.txt", b"data")
    file_id = _latest_file_id(app)

    bob_client = app.test_client()
    login(bob_client, "bob")
    response = bob_client.post(
        f"/sharing/share/{file_id}",
        data={"email": "charlie@example.com", "permission_type": "view"},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert _permission_count(app) == 0


def test_user_cannot_share_with_themselves(app, client, make_user):
    make_user()
    login(client, "alice")
    upload_file(client, "self.txt", b"data")
    file_id = _latest_file_id(app)

    response = share_file(client, file_id, "alice@example.com", "view")
    assert b"cannot share it with yourself" in response.data
    assert _permission_count(app) == 0


def test_cannot_share_with_unregistered_email(app, client, make_user):
    make_user()
    login(client, "alice")
    upload_file(client, "unknown.txt", b"data")
    file_id = _latest_file_id(app)

    response = share_file(client, file_id, "nobody@example.com", "view")
    assert b"No registered user" in response.data
    assert _permission_count(app) == 0


def test_cannot_share_with_deactivated_user(app, client, make_user):
    make_user()
    make_user(username="inactive", email="inactive@example.com", is_active=False)
    login(client, "alice")
    upload_file(client, "inactive.txt", b"data")
    file_id = _latest_file_id(app)

    response = share_file(client, file_id, "inactive@example.com", "view")
    assert b"deactivated" in response.data
    assert _permission_count(app) == 0


def test_duplicate_shares_update_existing_permission(app, client, make_user):
    make_user()
    bob_id = make_user(username="bob", email="bob@example.com")
    login(client, "alice")
    upload_file(client, "update.txt", b"data")
    file_id = _latest_file_id(app)

    share_file(client, file_id, "bob@example.com", "view")
    share_file(client, file_id, "bob@example.com", "download")

    assert _permission_count(app) == 1
    with app.app_context():
        permission = FilePermission.query.filter_by(
            file_id=file_id, shared_with_id=bob_id
        ).first()
        assert permission.permission_type == "download"
        assert permission.is_active is True


def test_revoked_permission_can_be_reactivated(app, client, make_user):
    make_user()
    bob_id = make_user(username="bob", email="bob@example.com")
    login(client, "alice")
    upload_file(client, "reactivate.txt", b"data")
    file_id = _latest_file_id(app)

    share_file(client, file_id, "bob@example.com", "view")
    with app.app_context():
        permission_id = FilePermission.query.filter_by(
            file_id=file_id, shared_with_id=bob_id
        ).first().id
    client.post(f"/sharing/revoke/{permission_id}", follow_redirects=True)

    share_file(client, file_id, "bob@example.com", "view")
    assert _permission_count(app) == 1
    with app.app_context():
        permission = db.session.get(FilePermission, permission_id)
        assert permission.is_active is True


def test_non_owner_cannot_revoke_permission(app, client, make_user):
    make_user()
    make_user(username="bob", email="bob@example.com")
    charlie_id = make_user(username="charlie", email="charlie@example.com")
    login(client, "alice")
    upload_file(client, "revoke-guard.txt", b"data")
    file_id = _latest_file_id(app)
    share_file(client, file_id, "charlie@example.com", "view")

    with app.app_context():
        permission_id = FilePermission.query.filter_by(
            file_id=file_id, shared_with_id=charlie_id
        ).first().id

    bob_client = app.test_client()
    login(bob_client, "bob")
    response = bob_client.post(f"/sharing/revoke/{permission_id}")
    assert response.status_code == 403

    with app.app_context():
        assert db.session.get(FilePermission, permission_id).is_active is True
