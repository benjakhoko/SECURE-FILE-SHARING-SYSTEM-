"""Administrator dashboard, user management, file oversight and security monitoring."""

from datetime import datetime, timedelta

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user
from sqlalchemy import func, or_

from app.extensions import db
from app.models import (
    SECURITY_EVENT_TYPES,
    ActivityLog,
    File,
    FilePermission,
    SecurityEvent,
    User,
)
from app.security.audit import log_activity, log_security_event
from app.security.permissions import admin_required
from app.timeutils import utcnow

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_files = File.query.count()
    total_shared_files = (
        db.session.query(func.count(func.distinct(FilePermission.file_id)))
        .filter(FilePermission.is_active.is_(True))
        .scalar()
    )
    total_storage = (
        db.session.query(func.coalesce(func.sum(File.file_size), 0)).scalar()
    )

    recent_activities = (
        ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    )
    recent_events = (
        SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(8).all()
    )
    security_event_count = SecurityEvent.query.count()

    today = utcnow().date()
    start_day = today - timedelta(days=6)
    start_dt = datetime.combine(start_day, datetime.min.time())

    uploads = (
        File.query.with_entities(File.uploaded_at)
        .filter(File.uploaded_at >= start_dt)
        .all()
    )
    signups = (
        User.query.with_entities(User.created_at)
        .filter(User.created_at >= start_dt)
        .all()
    )

    chart_labels, chart_uploads, chart_users = [], [], []
    for offset in range(7):
        day = start_day + timedelta(days=offset)
        chart_labels.append(day.strftime("%a"))
        chart_uploads.append(sum(1 for (ts,) in uploads if ts.date() == day))
        chart_users.append(sum(1 for (ts,) in signups if ts.date() == day))

    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        active_users=active_users,
        total_files=total_files,
        total_shared_files=total_shared_files,
        total_storage=total_storage,
        security_event_count=security_event_count,
        recent_activities=recent_activities,
        recent_events=recent_events,
        chart_labels=chart_labels,
        chart_uploads=chart_uploads,
        chart_users=chart_users,
    )


@admin_bp.route("/users")
@admin_required
def users():
    query = User.query
    search = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()

    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                User.full_name.ilike(like),
                User.username.ilike(like),
                User.email.ilike(like),
            )
        )
    if status == "active":
        query = query.filter(User.is_active.is_(True))
    elif status == "inactive":
        query = query.filter(User.is_active.is_(False))
    elif status == "admin":
        query = query.filter(User.role == "admin")

    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=15, error_out=False
    )

    return render_template(
        "admin/users.html",
        pagination=pagination,
        users=pagination.items,
        search=search,
        status=status,
    )


@admin_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def toggle_user(user_id: int):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if user.id == current_user.id:
        flash("You cannot deactivate your own administrator account.", "warning")
        return redirect(url_for("admin.users"))

    user.is_active = not user.is_active
    db.session.commit()

    state = "activated" if user.is_active else "deactivated"
    action = "account_activated" if user.is_active else "account_deactivated"
    log_activity(
        "account_status",
        f"Administrator {current_user.username} {state} account '{user.username}'.",
        user_id=current_user.id,
    )
    log_security_event(
        action,
        f"Account '{user.username}' was {state} by {current_user.username}.",
    )
    flash(f"Account '{user.username}' has been {state}.", "success")
    return redirect(url_for("admin.users", **(request.args.to_dict())))


@admin_bp.route("/files")
@admin_required
def files():
    query = File.query
    search = request.args.get("q", "").strip()

    if search:
        like = f"%{search}%"
        query = query.join(User, File.owner_id == User.id).filter(
            or_(
                File.original_filename.ilike(like),
                File.mime_type.ilike(like),
                User.username.ilike(like),
                User.email.ilike(like),
            )
        )

    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(File.uploaded_at.desc()).paginate(
        page=page, per_page=15, error_out=False
    )
    total_storage = db.session.query(
        func.coalesce(func.sum(File.file_size), 0)
    ).scalar()

    return render_template(
        "admin/files.html",
        pagination=pagination,
        files=pagination.items,
        search=search,
        total_storage=total_storage,
    )


@admin_bp.route("/security")
@admin_required
def security():
    query = SecurityEvent.query
    search = request.args.get("q", "").strip()
    event_type = request.args.get("type", "").strip()

    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                SecurityEvent.description.ilike(like),
                SecurityEvent.ip_address.ilike(like),
            )
        )
    if event_type in SECURITY_EVENT_TYPES:
        query = query.filter(SecurityEvent.event_type == event_type)

    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(SecurityEvent.timestamp.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    counts = dict(
        db.session.query(SecurityEvent.event_type, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.event_type)
        .all()
    )

    return render_template(
        "admin/security.html",
        pagination=pagination,
        events=pagination.items,
        event_types=SECURITY_EVENT_TYPES,
        selected_type=event_type,
        search=search,
        counts=counts,
    )
