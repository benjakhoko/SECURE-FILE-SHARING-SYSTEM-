"""Dashboard, profile management and activity log pages."""

from datetime import datetime, timedelta

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import func, or_
from sqlalchemy.orm import joinedload

from app.extensions import db
from app.forms import ChangePasswordForm, ProfileForm
from app.models import (
    ACTIVITY_ACTIONS,
    ActivityLog,
    File,
    FilePermission,
    PERMISSION_DOWNLOAD,
    PERMISSION_VIEW,
    User,
)
from app.security.audit import log_activity, log_security_event
from app.timeutils import utcnow

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))
    return redirect(url_for("auth.login"))


@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    user_id = current_user.id

    total_files = File.query.filter_by(owner_id=user_id).count()
    storage_used = (
        db.session.query(func.coalesce(func.sum(File.file_size), 0))
        .filter(File.owner_id == user_id)
        .scalar()
    )
    shared_by_me = FilePermission.query.filter_by(
        owner_id=user_id, is_active=True
    ).count()
    shared_with_me = FilePermission.query.filter_by(
        shared_with_id=user_id, is_active=True
    ).count()

    recent_activities = (
        ActivityLog.query.filter_by(user_id=user_id)
        .order_by(ActivityLog.timestamp.desc())
        .limit(8)
        .all()
    )
    recent_shared = (
        FilePermission.query.options(
            joinedload(FilePermission.file), joinedload(FilePermission.owner)
        )
        .filter_by(shared_with_id=user_id, is_active=True)
        .order_by(FilePermission.updated_at.desc())
        .limit(5)
        .all()
    )

    # Upload activity for the last 7 days (computed from real records).
    today = utcnow().date()
    start_day = today - timedelta(days=6)
    uploads = (
        File.query.with_entities(File.uploaded_at)
        .filter(File.owner_id == user_id, File.uploaded_at >= datetime.combine(start_day, datetime.min.time()))
        .all()
    )
    chart_labels = []
    chart_uploads = []
    for offset in range(7):
        day = start_day + timedelta(days=offset)
        chart_labels.append(day.strftime("%a"))
        chart_uploads.append(sum(1 for (ts,) in uploads if ts.date() == day))

    received = FilePermission.query.filter_by(
        shared_with_id=user_id, is_active=True
    ).all()
    view_count = sum(1 for p in received if p.permission_type == PERMISSION_VIEW)
    download_count = sum(1 for p in received if p.permission_type == PERMISSION_DOWNLOAD)

    return render_template(
        "dashboard/dashboard.html",
        total_files=total_files,
        storage_used=storage_used,
        shared_by_me=shared_by_me,
        shared_with_me=shared_with_me,
        recent_activities=recent_activities,
        recent_shared=recent_shared,
        chart_labels=chart_labels,
        chart_uploads=chart_uploads,
        view_count=view_count,
        download_count=download_count,
    )


@dashboard_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    profile_form = ProfileForm(obj=current_user)
    password_form = ChangePasswordForm()

    if request.method == "POST":
        if password_form.change_password.data:
            if password_form.validate_on_submit():
                if not current_user.check_password(password_form.current_password.data):
                    flash("Your current password is incorrect.", "danger")
                else:
                    current_user.set_password(password_form.new_password.data)
                    db.session.commit()
                    log_activity(
                        "password_change", "Account password was changed."
                    )
                    log_security_event(
                        "password_change", "Account password was changed."
                    )
                    flash("Your password has been updated.", "success")
                    return redirect(url_for("dashboard.profile"))
            else:
                flash("Please correct the password form errors.", "danger")
        elif profile_form.validate_on_submit():
            current_user.full_name = profile_form.full_name.data.strip()
            current_user.username = profile_form.username.data.strip()
            current_user.email = profile_form.email.data.strip().lower()
            db.session.commit()
            log_activity("profile_update", "Profile details were updated.")
            flash("Profile updated successfully.", "success")
            return redirect(url_for("dashboard.profile"))
        else:
            flash("Please correct the errors in the profile form.", "danger")

    return render_template(
        "dashboard/profile.html",
        profile_form=profile_form,
        password_form=password_form,
    )


@dashboard_bp.route("/activity-logs")
@login_required
def activity_logs():
    query = ActivityLog.query

    # Normal users only see their own records; admins see system-wide activity.
    if not current_user.is_admin:
        query = query.filter(ActivityLog.user_id == current_user.id)

    search = request.args.get("q", "").strip()
    action = request.args.get("action", "").strip()
    user_filter = request.args.get("user", "").strip()

    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                ActivityLog.description.ilike(like),
                ActivityLog.action.ilike(like),
                ActivityLog.ip_address.ilike(like),
            )
        )
    if action in ACTIVITY_ACTIONS:
        query = query.filter(ActivityLog.action == action)
    if user_filter and current_user.is_admin:
        query = query.join(ActivityLog.user).filter(
            User.username.ilike(f"%{user_filter}%")
        )

    page = request.args.get("page", 1, type=int)
    pagination = (
        query.order_by(ActivityLog.timestamp.desc())
        .paginate(
            page=page, per_page=15, error_out=False
        )
    )

    return render_template(
        "dashboard/activity_logs.html",
        pagination=pagination,
        logs=pagination.items,
        actions=ACTIVITY_ACTIONS,
        search=search,
        selected_action=action,
        user_filter=user_filter,
    )
