"""Registration, login and logout routes."""

from urllib.parse import urlparse

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func, or_

from app.extensions import db
from app.forms import LoginForm, RegistrationForm
from app.models import ROLE_USER, User
from app.security.audit import log_activity, log_security_event
from app.timeutils import utcnow

auth_bp = Blueprint("auth", __name__)


def _safe_next_url(target: str | None) -> str | None:
    """Only allow same-site relative redirects (prevents open redirects)."""
    if not target:
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return None
    if not target.startswith("/") or target.startswith("//"):
        return None
    return target


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            full_name=form.full_name.data.strip(),
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            role=ROLE_USER,
            is_active=True,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        log_activity(
            "registration",
            f"Account registered for {user.username}.",
            user_id=user.id,
        )
        flash("Your account was created. Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.identifier.data.strip()
        user = User.query.filter(
            or_(
                func.lower(User.username) == identifier.lower(),
                func.lower(User.email) == identifier.lower(),
            )
        ).first()

        if user is None or not user.check_password(form.password.data):
            log_security_event(
                "login_failed",
                f"Failed login attempt for '{identifier[:80]}'.",
                user_id=user.id if user else None,
            )
            flash("Invalid username/email or password.", "danger")
            return render_template("auth/login.html", form=form)

        if not user.is_active:
            log_security_event(
                "login_failed",
                f"Login attempt on deactivated account '{user.username}'.",
                user_id=user.id,
            )
            flash("This account has been deactivated. Contact an administrator.", "danger")
            return render_template("auth/login.html", form=form), 403

        login_user(user, remember=form.remember.data)
        session.permanent = True
        user.last_login_at = utcnow()
        db.session.commit()
        log_activity("login", f"{user.username} signed in.", user_id=user.id)

        flash(f"Welcome back, {user.full_name.split()[0]}!", "success")
        return redirect(
            _safe_next_url(request.args.get("next")) or url_for("dashboard.dashboard")
        )

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    username = current_user.username
    user_id = current_user.id
    logout_user()
    log_activity("logout", f"{username} signed out.", user_id=user_id)
    flash("You have been signed out securely.", "info")
    return redirect(url_for("auth.login"))
