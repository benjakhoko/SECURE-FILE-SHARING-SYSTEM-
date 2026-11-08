"""File upload, encryption, download and integrity tests."""

from pathlib import Path

import pytest

from app.extensions import db
from app.models import File, FilePermission, SecurityEvent
from app.security.encryption import EncryptionError, decrypt_bytes
from tests.helpers import login, logout, share_file, upload_file


def _latest_file(app):
    with app.app_context():
        file = File.query.order_by(File.id.desc()).first()
        return (
            file.id,
            file.stored_filename,
            file.original_filename,
            file.file_size,
            file.owner_id,
        )


def _permission_id(app, file_id, recipient_id):
    with app.app_context():
        permission = FilePermission.query.filter_by(
            file_id=file_id, shared_with_id=recipient_id
        ).first()
        return permission.id if permission else None


def test_upload_encrypts_at_rest_and_download_roundtrip(app, client, make_user):
    make_user()
    login(client, "alice")
    content = b"Top secret quarterly financial report"
    response = upload_file(client, "report.txt", content)
    assert response.status_code == 200
    assert b"encrypted" in response.data.lower()

    file_id, stored_name, original, size, _ = _latest_file(app)
    assert original == "report.txt"
    assert size == len(content)
    assert stored_name != original
    assert stored_name.endswith(".enc")

    stored_path = Path(app.config["UPLOAD_FOLDER"]) / stored_name
    assert stored_path.exists()
    assert "static" not in str(stored_path).lower()
    blob = stored_path.read_bytes()

    assert blob.startswith(b"SFSE\x01")
    assert content not in blob

    with app.app_context():
        record = db.session.get(File, file_id)
        assert record.encryption_status == "AES-256-GCM"
        assert record.mime_type == "text/plain"

    download = client.get(f"/files/{file_id}/download")
    assert download.status_code == 200
    assert download.data == content
    assert download.headers.get("X-Content-Type-Options") == "nosniff"

    preview = client.get(f"/files/{file_id}/preview")
    assert preview.status_code == 200
    assert preview.data == content


def test_upload_rejects_disallowed_extension(app, client, make_user):
    make_user()
    login(client, "alice")
    response = upload_file(client, "malware.exe", b"MZ\x90\x00malicious")
    assert b"Unsupported file type" in response.data
    with app.app_context():
        assert File.query.count() == 0
        assert SecurityEvent.query.filter_by(
            event_type="file_validation_failure"
        ).count() == 1


def test_upload_rejects_spoofed_content(app, client, make_user):
    make_user()
    login(client, "alice")
    response = upload_file(client, "fake.pdf", b"this is definitely not a pdf")
    assert b"does not match its extension" in response.data
    with app.app_context():
        assert File.query.count() == 0


def test_unauthorized_user_cannot_download_private_file(app, client, make_user):
    alice_id = make_user()
    make_user(username="bob", email="bob@example.com")
    login(client, "alice")
    upload_file(client, "private.txt", b"alice private data")
    file_id, _, _, _, _ = _latest_file(app)

    logout(client)
    login(client, "bob", password="Password123")

    response = client.get(f"/files/{file_id}/download")
    assert response.status_code == 403
    detail = client.get(f"/files/{file_id}")
    assert detail.status_code == 403

    with app.app_context():
        assert SecurityEvent.query.filter_by(
            event_type="unauthorized_access"
        ).count() >= 1
        # The owner is still Alice.
        assert db.session.get(File, file_id).owner_id == alice_id


def test_view_permission_prevents_download_but_allows_preview(app, client, make_user):
    make_user()
    bob_id = make_user(username="bob", email="bob@example.com")
    login(client, "alice")
    content = b"view only content"
    upload_file(client, "memo.txt", content)
    file_id, _, _, _, _ = _latest_file(app)

    response = share_file(client, file_id, "bob@example.com", "view")
    assert response.status_code == 200

    bob_client = app.test_client()
    login(bob_client, "bob")
    shared_page = bob_client.get("/sharing/shared-with-me")
    assert b"memo.txt" in shared_page.data

    preview = bob_client.get(f"/files/{file_id}/preview")
    assert preview.status_code == 200
    assert preview.data == content

    download = bob_client.get(f"/files/{file_id}/download")
    assert download.status_code == 403

    # Owner upgrades access to download.
    share_file(client, file_id, "bob@example.com", "download")
    download = bob_client.get(f"/files/{file_id}/download")
    assert download.status_code == 200
    assert download.data == content

    with app.app_context():
        permission = FilePermission.query.filter_by(
            file_id=file_id, shared_with_id=bob_id
        ).first()
        assert permission.permission_type == "download"
        assert permission.is_active is True


def test_owner_can_revoke_access_immediately(app, client, make_user):
    make_user()
    bob_id = make_user(username="bob", email="bob@example.com")
    login(client, "alice")
    upload_file(client, "shared.txt", b"shared data")
    file_id, _, _, _, _ = _latest_file(app)
    share_file(client, file_id, "bob@example.com", "download")

    bob_client = app.test_client()
    login(bob_client, "bob")
    assert bob_client.get(f"/files/{file_id}/download").status_code == 200

    permission_id = _permission_id(app, file_id, bob_id)
    revoke = client.post(f"/sharing/revoke/{permission_id}", follow_redirects=True)
    assert revoke.status_code == 200

    denied = bob_client.get(f"/files/{file_id}/download")
    assert denied.status_code == 403
    page = bob_client.get("/sharing/shared-with-me")
    assert b"No files shared with you" in page.data


def test_tampered_encrypted_file_fails_authentication(app, client, make_user):
    make_user()
    login(client, "alice")
    upload_file(client, "tamper.txt", b"integrity protected content")
    file_id, stored_name, _, _, _ = _latest_file(app)

    path = Path(app.config["UPLOAD_FOLDER"]) / stored_name
    blob = bytearray(path.read_bytes())
    blob[-1] = blob[-1] ^ 0xFF  # flip a ciphertext/tag bit
    path.write_bytes(bytes(blob))

    with app.app_context():
        with pytest.raises(EncryptionError):
            decrypt_bytes(bytes(blob))

    response = client.get(f"/files/{file_id}/download", follow_redirects=True)
    assert response.status_code == 200
    assert b"could not be decrypted" in response.data

    with app.app_context():
        assert SecurityEvent.query.filter_by(
            event_type="decryption_failure"
        ).count() >= 1


def test_owner_can_delete_file_and_ciphertext(app, client, make_user):
    make_user()
    login(client, "alice")
    upload_file(client, "delete-me.txt", b"temporary")
    file_id, stored_name, _, _, _ = _latest_file(app)
    path = Path(app.config["UPLOAD_FOLDER"]) / stored_name
    assert path.exists()

    response = client.post(f"/files/{file_id}/delete", follow_redirects=True)
    assert response.status_code == 200
    assert b"was deleted" in response.data

    with app.app_context():
        assert db.session.get(File, file_id) is None
    assert not path.exists()
