"""Activity and security event logging helpers.

Logging never raises into the request flow: a logging failure must not turn a
successful file operation into a server error.
"""

from flask import has_request_context, request
from flask_login import current_user

from app.extensions import db
from app.models import ActivityLog, SecurityEvent


def client_ip() -> str:
    """Best-effort client IP extraction (respects one proxy hop)."""
    if not has_request_context():
        return "cli"
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64] or "unknown"
    return (request.remote_addr or "unknown")[:64]


def _current_user_id() -> int | None:
    if has_request_context() and current_user.is_authenticated:
        return current_user.id
    return None


def log_activity(
    action: str,
    description: str,
    user_id: int | None = None,
    file_id: int | None = None,
    commit: bool = True,
) -> ActivityLog | None:
    """Record an activity log entry."""
    if user_id is None:
        user_id = _current_user_id()
    entry = ActivityLog(
        user_id=user_id,
        action=action,
        description=description[:500],
        file_id=file_id,
        ip_address=client_ip(),
    )
    try:
        db.session.add(entry)
        if commit:
            db.session.commit()
        else:
            db.session.flush()
        return entry
    except Exception:  # pragma: no cover - defensive
        db.session.rollback()
        return None


def log_security_event(
    event_type: str,
    description: str,
    user_id: int | None = None,
    commit: bool = True,
) -> SecurityEvent | None:
    """Record a security event for administrator monitoring."""
    if user_id is None:
        user_id = _current_user_id()
    entry = SecurityEvent(
        user_id=user_id,
        event_type=event_type,
        description=description[:500],
        ip_address=client_ip(),
    )
    try:
        db.session.add(entry)
        if commit:
            db.session.commit()
        else:
            db.session.flush()
        return entry
    except Exception:  # pragma: no cover - defensive
        db.session.rollback()
        return None
