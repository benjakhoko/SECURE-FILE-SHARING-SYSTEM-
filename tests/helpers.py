"""Test helper functions."""

from io import BytesIO

from app.extensions import db
from app.models import File, FilePermission, User


def login(client, identifier, password="Password123"):
    return client.post(
        "/login",
        data={"identifier": identifier, "password": password},
        follow_redirects=True,
    )


def logout(client):
    return client.post("/logout", follow_redirects=True)


def register(client, full_name="Test User", username="tester", email=None, password="Password123"):
    return client.post(
        "/register",
        data={
            "full_name": full_name,
            "username": username,
            "email": email or f"{username}@example.com",
            "password": password,
            "confirm_password": password,
        },
        follow_redirects=True,
    )


def upload_file(client, filename="report.txt", content=b"Confidential quarterly report"):
    return client.post(
        "/files/upload",
        data={"file": (BytesIO(content), filename)},
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def share_file(client, file_id, email, permission_type="view"):
    return client.post(
        f"/sharing/share/{file_id}",
        data={"email": email, "permission_type": permission_type},
        follow_redirects=True,
    )


def get_file(app, file_id):
    with app.app_context():
        return db.session.get(File, file_id)


def get_permission(app, file_id, recipient_id):
    with app.app_context():
        return FilePermission.query.filter_by(
            file_id=file_id, shared_with_id=recipient_id
        ).first()


def get_user(app, username):
    with app.app_context():
        return User.query.filter_by(username=username).first()
