"""Authentication and account security tests."""

from app.extensions import db
from app.models import SecurityEvent, User
from tests.helpers import login, logout, register


def test_register_creates_user_with_hashed_password(app, client):
    response = register(client, username="newuser", email="newuser@example.com")
    assert response.status_code == 200
    assert b"Your account was created" in response.data

    with app.app_context():
        user = User.query.filter_by(username="newuser").first()
        assert user is not None
        assert user.email == "newuser@example.com"
        assert user.password_hash != "Password123"
        assert user.check_password("Password123")
        assert user.role == "user"
        assert user.is_active is True


def test_register_rejects_duplicate_email(app, client, make_user):
    make_user(username="alice", email="alice@example.com")
    response = register(client, username="alice2", email="ALICE@example.com")
    assert b"already exists" in response.data
    with app.app_context():
        assert User.query.count() == 1


def test_register_rejects_weak_password(app, client):
    response = register(client, username="weak", email="weak@example.com", password="abcdefgh")
    assert b"at least one number" in response.data
    with app.app_context():
        assert User.query.filter_by(username="weak").first() is None


def test_login_success(app, client, make_user):
    make_user()
    response = login(client, "alice")
    assert response.status_code == 200
    assert b"Welcome back" in response.data
    with client.session_transaction() as session:
        assert "_user_id" in session
    with app.app_context():
        assert (
            SecurityEvent.query.filter_by(event_type="login_failed").count() == 0
        )


def test_login_incorrect_password_is_rejected(app, client, make_user):
    make_user()
    response = login(client, "alice", password="WrongPassword1")
    assert b"Invalid username/email or password" in response.data
    with client.session_transaction() as session:
        assert "_user_id" not in session
    with app.app_context():
        assert (
            SecurityEvent.query.filter_by(event_type="login_failed").count() == 1
        )


def test_deactivated_account_cannot_login(app, client, make_user):
    make_user(is_active=False)
    response = login(client, "alice")
    assert b"deactivated" in response.data
    with client.session_transaction() as session:
        assert "_user_id" not in session


def test_logout_clears_session(app, client, make_user):
    make_user()
    login(client, "alice")
    response = logout(client)
    assert response.status_code == 200
    with client.session_transaction() as session:
        assert "_user_id" not in session


def test_logout_rejects_get_requests(app, client, make_user):
    make_user()
    login(client, "alice")
    response = client.get("/logout")
    assert response.status_code == 405
    with client.session_transaction() as session:
        assert "_user_id" in session


def test_deactivation_invalidates_existing_session(app, client, make_user):
    user_id = make_user()
    login(client, "alice")

    with app.app_context():
        user = db.session.get(User, user_id)
        user.is_active = False
        db.session.commit()

    response = client.get("/dashboard", follow_redirects=True)
    assert response.status_code == 200
    assert b"Please sign in" in response.data
