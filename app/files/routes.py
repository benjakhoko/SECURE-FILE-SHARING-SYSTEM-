"""Upload, list, inspect, preview, download and delete files."""

import uuid
from io import BytesIO
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import or_

from app.extensions import db
from app.forms import UploadForm
from app.models import ActivityLog, File, FilePermission
from app.security.audit import log_activity, log_security_event
from app.security.encryption import EncryptionError, decrypt_bytes, encrypt_bytes
from app.security.file_validation import (
    FileValidationError,
    clean_original_filename,
    extension_of,
    is_previewable,
    mime_for,
    validate_content,
    validate_extension,
)
from app.security.permissions import (
    can_download,
    can_preview,
    can_view_metadata,
    deny_access,
    get_active_permission,
    is_owner,
)

files_bp = Blueprint("files", __name__, url_prefix="/files")


def _upload_dir() -> Path:
    return Path(current_app.config["UPLOAD_FOLDER"]).resolve()


def _storage_path(stored_filename: str) -> Path:
    """Resolve a stored filename and prevent directory traversal."""
    base = _upload_dir()
    candidate = (base / stored_filename).resolve()
    if base not in candidate.parents:
        abort(400)
    return candidate


def _get_file_or_404(file_id: int) -> File:
    file = db.session.get(File, file_id)
    if file is None:
        abort(404)
    return file


@files_bp.route("")
@login_required
def list_files():
    query = File.query.filter_by(owner_id=current_user.id)
    search = request.args.get("q", "").strip()
    sort = request.args.get("sort", "newest")

    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                File.original_filename.ilike(like),
                File.mime_type.ilike(like),
            )
        )

    if sort == "oldest":
        query = query.order_by(File.uploaded_at.asc())
    elif sort == "name":
        query = query.order_by(File.original_filename.asc())
    elif sort == "largest":
        query = query.order_by(File.file_size.desc())
    else:
        query = query.order_by(File.uploaded_at.desc())

    page = request.args.get("page", 1, type=int)
    pagination = query.paginate(
        page=page, per_page=current_app.config["ITEMS_PER_PAGE"], error_out=False
    )

    return render_template(
        "files/list.html",
        pagination=pagination,
        files=pagination.items,
        search=search,
        sort=sort,
    )


@files_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    form = UploadForm()
    max_mb = current_app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024)
    allowed = ", ".join(sorted(current_app.config["ALLOWED_EXTENSIONS"])).upper()

    if form.validate_on_submit():
        upload_stream = form.file.data
        try:
            original_name = clean_original_filename(upload_stream.filename)
            extension = extension_of(original_name)
            validate_extension(extension)
            data = upload_stream.read()
            validate_content(data, extension)
        except FileValidationError as exc:
            log_security_event(
                "file_validation_failure",
                f"Rejected upload from {current_user.username}: {exc}",
            )
            flash(str(exc), "danger")
            return render_template(
                "files/upload.html", form=form, max_mb=max_mb, allowed=allowed
            )

        try:
            encrypted_blob = encrypt_bytes(data)
        except EncryptionError:
            current_app.logger.exception("Encryption failed during upload")
            log_security_event(
                "file_validation_failure",
                f"Encryption failed while processing an upload from {current_user.username}.",
            )
            flash(
                "The file could not be encrypted due to a server configuration error. "
                "Contact the administrator.",
                "danger",
            )
            return render_template(
                "files/upload.html", form=form, max_mb=max_mb, allowed=allowed
            )

        stored_filename = f"{uuid.uuid4().hex}.enc"
        try:
            _storage_path(stored_filename).write_bytes(encrypted_blob)
        except OSError:
            current_app.logger.exception("Failed to write encrypted file to disk")
            flash("The encrypted file could not be saved. Please try again.", "danger")
            return render_template(
                "files/upload.html", form=form, max_mb=max_mb, allowed=allowed
            )

        file = File(
            owner_id=current_user.id,
            original_filename=original_name,
            stored_filename=stored_filename,
            file_size=len(data),
            mime_type=mime_for(extension),
            encryption_status="AES-256-GCM",
        )
        db.session.add(file)
        db.session.commit()
        log_activity(
            "upload",
            f"Uploaded and encrypted '{original_name}' ({len(data)} bytes).",
            file_id=file.id,
        )
        flash("File encrypted with AES-256-GCM and uploaded successfully.", "success")
        return redirect(url_for("files.detail", file_id=file.id))

    return render_template(
        "files/upload.html", form=form, max_mb=max_mb, allowed=allowed
    )


@files_bp.route("/<int:file_id>")
@login_required
def detail(file_id: int):
    file = _get_file_or_404(file_id)
    if not can_view_metadata(file, current_user):
        deny_access(
            f"{current_user.username} attempted to view metadata for file #{file_id}."
        )

    owner = is_owner(file, current_user)
    permissions = []
    if owner:
        permissions = (
            file.permissions.order_by(FilePermission.created_at.desc()).all()
        )

    return render_template(
        "files/detail.html",
        file=file,
        permissions=permissions,
        owner=owner,
        allow_download=can_download(file, current_user),
        allow_preview=can_preview(file, current_user),
        my_permission=get_active_permission(file, current_user),
    )


@files_bp.route("/<int:file_id>/download")
@login_required
def download(file_id: int):
    file = _get_file_or_404(file_id)
    if not can_download(file, current_user):
        deny_access(
            f"{current_user.username} attempted to download file #{file_id} without permission."
        )

    path = _storage_path(file.stored_filename)
    try:
        encrypted_blob = path.read_bytes()
        plaintext = decrypt_bytes(encrypted_blob)
    except (OSError, EncryptionError):
        current_app.logger.exception("Failed to read/decrypt file %s", file.id)
        log_security_event(
            "decryption_failure",
            f"Decryption or read failure for file #{file.id} ('{file.original_filename}').",
        )
        flash(
            "The file could not be decrypted. It may have been modified or is unavailable.",
            "danger",
        )
        return redirect(url_for("files.detail", file_id=file.id))

    log_activity(
        "download",
        f"Downloaded '{file.original_filename}'.",
        file_id=file.id,
    )

    response = send_file(
        BytesIO(plaintext),
        mimetype=file.mime_type,
        as_attachment=True,
        download_name=file.original_filename,
        max_age=0,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@files_bp.route("/<int:file_id>/preview")
@login_required
def preview(file_id: int):
    file = _get_file_or_404(file_id)
    if not can_preview(file, current_user):
        deny_access(
            f"{current_user.username} attempted to preview file #{file_id} without permission."
        )

    if not is_previewable(file.mime_type):
        flash("This file type cannot be previewed. Download it to view it.", "warning")
        return redirect(url_for("files.detail", file_id=file.id))

    path = _storage_path(file.stored_filename)
    try:
        plaintext = decrypt_bytes(path.read_bytes())
    except (OSError, EncryptionError):
        current_app.logger.exception("Failed to read/decrypt file %s for preview", file.id)
        log_security_event(
            "decryption_failure",
            f"Preview decryption failure for file #{file.id}.",
        )
        flash("The file could not be decrypted for preview.", "danger")
        return redirect(url_for("files.detail", file_id=file.id))

    log_activity(
        "preview",
        f"Previewed '{file.original_filename}'.",
        file_id=file.id,
    )

    response = send_file(
        BytesIO(plaintext),
        mimetype=file.mime_type,
        as_attachment=False,
        download_name=file.original_filename,
        max_age=0,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@files_bp.route("/<int:file_id>/delete", methods=["POST"])
@login_required
def delete(file_id: int):
    file = _get_file_or_404(file_id)
    if not is_owner(file, current_user):
        deny_access(
            f"{current_user.username} attempted to delete file #{file_id} without ownership."
        )

    stored_filename = file.stored_filename
    original_name = file.original_filename

    # Detach activity references so historical logs remain readable.
    ActivityLog.query.filter_by(file_id=file.id).update({"file_id": None})
    db.session.delete(file)
    db.session.commit()

    try:
        _storage_path(stored_filename).unlink(missing_ok=True)
    except OSError:
        current_app.logger.warning("Could not remove encrypted file %s", stored_filename)

    log_activity("delete", f"Deleted '{original_name}'.")
    flash(f"'{original_name}' was deleted.", "success")
    return redirect(url_for("files.list_files"))
