"""Share files, list shared files and manage/revoke permissions."""

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import func, or_

from app.extensions import db
from app.forms import ShareForm
from app.models import File, FilePermission, User
from app.security.audit import log_activity, log_security_event
from app.security.permissions import deny_access, is_owner
from app.timeutils import utcnow

sharing_bp = Blueprint("sharing", __name__, url_prefix="/sharing")


def _get_file_or_404(file_id: int) -> File:
    file = db.session.get(File, file_id)
    if file is None:
        abort(404)
    return file


def _require_owner(file: File) -> None:
    if not is_owner(file, current_user):
        deny_access(
            f"{current_user.username} attempted to manage sharing for file "
            f"#{file.id} without ownership."
        )


@sharing_bp.route("/share/<int:file_id>", methods=["GET", "POST"])
@login_required
def share(file_id: int):
    file = _get_file_or_404(file_id)
    _require_owner(file)

    form = ShareForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        recipient = User.query.filter(func.lower(User.email) == email).first()

        if recipient is None:
            flash("No registered user was found with that email address.", "danger")
            return render_template("sharing/share.html", form=form, file=file)

        if recipient.id == current_user.id:
            flash("You already own this file and cannot share it with yourself.", "warning")
            return render_template("sharing/share.html", form=form, file=file)

        if not recipient.is_active:
            flash("That account is deactivated and cannot receive shared files.", "warning")
            return render_template("sharing/share.html", form=form, file=file)

        existing = FilePermission.query.filter_by(
            file_id=file.id, shared_with_id=recipient.id
        ).first()

        if existing:
            old_type = existing.permission_type
            existing.permission_type = form.permission_type.data
            existing.owner_id = file.owner_id
            existing.is_active = True
            existing.updated_at = utcnow()
            db.session.commit()
            log_activity(
                "permission_change",
                f"Updated access for '{file.original_filename}' to "
                f"{recipient.email} ({old_type} -> {existing.permission_type}).",
                file_id=file.id,
            )
            log_security_event(
                "permission_change",
                f"Permission on file #{file.id} for {recipient.email} changed to "
                f"{existing.permission_type}.",
            )
            flash(
                f"Access for {recipient.email} updated to {existing.permission_label}.", 
                "success",
            )
        else:
            permission = FilePermission(
                file_id=file.id,
                owner_id=file.owner_id,
                shared_with_id=recipient.id,
                permission_type=form.permission_type.data,
                is_active=True,
            )
            db.session.add(permission)
            db.session.commit()
            log_activity(
                "share",
                f"Shared '{file.original_filename}' with {recipient.email} "
                f"({permission.permission_label}).",
                file_id=file.id,
            )
            log_activity(
                "share",
                f"'{file.original_filename}' was shared with you by "
                f"{current_user.username} ({permission.permission_label}).",
                user_id=recipient.id,
                file_id=file.id,
            )
            flash(
                f"'{file.original_filename}' shared with {recipient.email} "
                f"({permission.permission_label}).",
                "success",
            )

        return redirect(url_for("sharing.permissions", file_id=file.id))

    return render_template("sharing/share.html", form=form, file=file)


@sharing_bp.route("/shared-with-me")
@login_required
def shared_with_me():
    query = (
        FilePermission.query.join(File, FilePermission.file_id == File.id)
        .filter(
            FilePermission.shared_with_id == current_user.id,
            FilePermission.is_active.is_(True),
        )
    )

    search = request.args.get("q", "").strip()
    if search:
        query = query.filter(File.original_filename.ilike(f"%{search}%"))

    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(FilePermission.updated_at.desc()).paginate(
        page=page, per_page=current_app.config["ITEMS_PER_PAGE"], error_out=False
    )

    return render_template(
        "sharing/shared_with_me.html",
        pagination=pagination,
        permissions=pagination.items,
        search=search,
    )


@sharing_bp.route("/shared-by-me")
@login_required
def shared_by_me():
    query = (
        FilePermission.query.join(File, FilePermission.file_id == File.id)
        .filter(FilePermission.owner_id == current_user.id)
    )

    search = request.args.get("q", "").strip()
    if search:
        like = f"%{search}%"
        query = query.join(User, FilePermission.shared_with_id == User.id).filter(
            or_(File.original_filename.ilike(like), User.email.ilike(like))
        )

    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(FilePermission.updated_at.desc()).paginate(
        page=page, per_page=current_app.config["ITEMS_PER_PAGE"], error_out=False
    )

    return render_template(
        "sharing/shared_by_me.html",
        pagination=pagination,
        permissions=pagination.items,
        search=search,
    )


@sharing_bp.route("/permissions")
@login_required
def permissions_index():
    query = File.query.filter_by(owner_id=current_user.id)
    search = request.args.get("q", "").strip()
    if search:
        query = query.filter(File.original_filename.ilike(f"%{search}%"))

    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(File.uploaded_at.desc()).paginate(
        page=page, per_page=current_app.config["ITEMS_PER_PAGE"], error_out=False
    )

    return render_template(
        "sharing/permissions_index.html",
        pagination=pagination,
        files=pagination.items,
        search=search,
    )


@sharing_bp.route("/permissions/<int:file_id>")
@login_required
def permissions(file_id: int):
    file = _get_file_or_404(file_id)
    _require_owner(file)

    permissions = file.permissions.order_by(FilePermission.updated_at.desc()).all()
    active_count = sum(1 for p in permissions if p.is_active)

    return render_template(
        "sharing/permissions.html",
        file=file,
        permissions=permissions,
        active_count=active_count,
    )


@sharing_bp.route("/revoke/<int:permission_id>", methods=["POST"])
@login_required
def revoke(permission_id: int):
    permission = db.session.get(FilePermission, permission_id)
    if permission is None:
        abort(404)

    if permission.owner_id != current_user.id:
        deny_access(
            f"{current_user.username} attempted to revoke permission "
            f"#{permission_id} without ownership."
        )

    if not permission.is_active:
        flash("That permission is already revoked.", "info")
        return redirect(
            url_for("sharing.permissions", file_id=permission.file_id)
        )

    permission.is_active = False
    permission.updated_at = utcnow()
    db.session.commit()

    log_activity(
        "revoke",
        f"Revoked access to '{permission.file.original_filename}' for "
        f"{permission.shared_with.email}.",
        file_id=permission.file_id,
    )
    log_activity(
        "revoke",
        f"Your access to '{permission.file.original_filename}' was revoked by "
        f"{current_user.username}.",
        user_id=permission.shared_with_id,
        file_id=permission.file_id,
    )
    log_security_event(
        "permission_change",
        f"Access revoked on file #{permission.file_id} for "
        f"{permission.shared_with.email}.",
    )

    flash(f"Access for {permission.shared_with.email} has been revoked.", "success")
    return redirect(url_for("sharing.permissions", file_id=permission.file_id))
