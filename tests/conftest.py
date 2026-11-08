"""Shared pytest fixtures."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import ROLE_ADMIN, ROLE_USER, User  # noqa: E402
from app.security.encryption import generate_key  # noqa: E402


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            "FILE_ENCRYPTION_KEY": generate_key(),
            "SECRET_KEY": "test-secret-key",
        }
    )
    # Only hold an app context while preparing/cleaning the database. Keeping one
    # open during the whole test would let Flask-Login's request-local user cache
    # (stored on ``g``) leak between test client requests.
    with application.app_context():
        db.create_all()

    yield application

    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def make_user(app):
    """Factory that creates a user and returns its database id."""

    def _make_user(
        username="alice",
        email="alice@example.com",
        password="Password123",
        role=ROLE_USER,
        is_active=True,
        full_name=None,
    ):
        with app.app_context():
            user = User(
                full_name=full_name or username.title(),
                username=username,
                email=email,
                role=role,
                is_active=is_active,
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            return user.id

    return _make_user


@pytest.fixture()
def admin_id(make_user):
    return make_user(
        username="admin",
        email="admin@example.com",
        password="AdminPass123",
        role=ROLE_ADMIN,
        full_name="Admin User",
    )
