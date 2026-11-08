"""Application factory for the Secure File Sharing System."""

import os

from flask import Flask, flash, redirect, render_template, url_for
from flask_login import current_user

from app.extensions import csrf, db, login_manager, migrate
from app.models import ActivityLog, User
from app.security.encryption import EncryptionError, validate_key
from app.timeutils import utcnow

APP_NAME = "CipherVault"


def create_app(config_overrides: dict | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object("config.Config")
    if config_overrides:
        app.config.update(config_overrides)

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to access that page."
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"

    register_blueprints(app)
    register_error_handlers(app)
    register_template_helpers(app)
    register_cli(app)

    if app.config.get("FILE_ENCRYPTION_KEY"):
        with app.app_context():
            try:
                validate_key()
            except EncryptionError:
                app.logger.error(
                    "FILE_ENCRYPTION_KEY is set but invalid. File operations will fail."
                )
    else:
        app.logger.warning(
            "FILE_ENCRYPTION_KEY is not configured. Run 'flask generate-key' "
            "and add the value to your .env file."
        )

    return app


@login_manager.user_loader
def load_user(user_id: str):
    try:
        user = db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
    # Deactivating an account immediately invalidates existing sessions.
    if user is None or not user.is_active:
        return None
    return user


def register_blueprints(app: Flask) -> None:
    from app.admin.routes import admin_bp
    from app.auth.routes import auth_bp
    from app.dashboard.routes import dashboard_bp
    from app.files.routes import files_bp
    from app.sharing.routes import sharing_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(sharing_bp)
    app.register_blueprint(admin_bp)


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(403)
    def forbidden(error):
        return (
            render_template(
                "errors/error.html",
                code=403,
                title="Access denied",
                message="You do not have permission to perform this action.",
            ),
            403,
        )

    @app.errorhandler(404)
    def not_found(error):
        return (
            render_template(
                "errors/error.html",
                code=404,
                title="Page not found",
                message="The page or resource you requested could not be found.",
            ),
            404,
        )

    @app.errorhandler(413)
    def payload_too_large(error):
        limit_mb = app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024)
        message = f"That file exceeds the {limit_mb:.0f} MB upload limit."
        if current_user.is_authenticated:
            flash(message, "danger")
            return redirect(url_for("files.upload"))
        return (
            render_template(
                "errors/error.html", code=413, title="File too large", message=message
            ),
            413,
        )

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        app.logger.exception("Unhandled server error")
        return (
            render_template(
                "errors/error.html",
                code=500,
                title="Something went wrong",
                message="An unexpected error occurred. No sensitive details are shown.",
            ),
            500,
        )


def register_template_helpers(app: Flask) -> None:
    @app.template_filter("datetime")
    def format_datetime(value, fmt: str = "%d %b %Y, %H:%M"):
        if not value:
            return "—"
        return value.strftime(fmt)

    @app.template_filter("day")
    def format_day(value):
        if not value:
            return "—"
        return value.strftime("%d %b %Y")

    @app.template_filter("humanize")
    def humanize_action(value: str) -> str:
        return (value or "").replace("_", " ").title()

    @app.template_filter("file_icon")
    def file_icon(filename: str) -> str:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        return {
            "pdf": "bi-file-earmark-pdf",
            "doc": "bi-file-earmark-word",
            "docx": "bi-file-earmark-word",
            "xls": "bi-file-earmark-excel",
            "xlsx": "bi-file-earmark-excel",
            "csv": "bi-file-earmark-spreadsheet",
            "txt": "bi-file-earmark-text",
            "jpg": "bi-file-earmark-image",
            "jpeg": "bi-file-earmark-image",
            "png": "bi-file-earmark-image",
            "zip": "bi-file-earmark-zip",
        }.get(ext, "bi-file-earmark")

    @app.context_processor
    def inject_globals():
        notifications = []
        if current_user.is_authenticated:
            notifications = (
                ActivityLog.query.filter_by(user_id=current_user.id)
                .order_by(ActivityLog.timestamp.desc())
                .limit(5)
                .all()
            )
        return {
            "app_name": APP_NAME,
            "notifications": notifications,
            "current_year": utcnow().year,
        }


def register_cli(app: Flask) -> None:
    from app.cli import register_commands

    register_commands(app)
