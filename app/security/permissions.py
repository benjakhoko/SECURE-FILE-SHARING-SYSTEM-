"""Backend authorization helpers.

Every file operation must call these helpers. Frontend button visibility is
never treated as a security control.
"""

from functools import wraps

from flask import abort
from flask_login import current_user

from app.extensions import login_manager
from app.models import (
    PERMISSION_DOWNLOAD,
    PERMISSION_VIEW,
    FilePermission,
)
from app.security.audit import log_security_event


def admin_required(view):
    """Allow only authenticated administrators; log denied attempts."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not current_user.is_admin:
            log_security_event(
                "unauthorized_access",
                "Non-administrator attempted to access an admin route.",
            )
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def get_active_permission(file, user) -> FilePermission | None:
    """Return the active permission record for ``user`` on ``file``, if any."""
    if not getattr(user, "is_authenticated", False):
        return None
    if file is None:
        return None
    return FilePermission.query.filter_by(
        file_id=file.id, shared_with_id=user.id, is_active=True
    ).first()


def is_owner(file, user) -> bool:
    return bool(
        getattr(user, "is_authenticated", False) and file is not None and file.owner_id == user.id
    )


def can_view_metadata(file, user) -> bool:
    """Owners, active recipients and admins may see file metadata."""
    if is_owner(file, user):
        return True
    if getattr(user, "is_admin", False):
        return True
    return get_active_permission(file, user) is not None


def can_preview(file, user) -> bool:
    """Owners and active recipients (view or download) may preview."""
    if is_owner(file, user):
        return True
    permission = get_active_permission(file, user)
    return permission is not None and permission.permission_type in {
        PERMISSION_VIEW,
        PERMISSION_DOWNLOAD,
    }


def can_download(file, user) -> bool:
    """Only owners and recipients with the download permission may download."""
    if is_owner(file, user):
        return True
    permission = get_active_permission(file, user)
    return permission is not None and permission.permission_type == PERMISSION_DOWNLOAD


def deny_access(description: str) -> None:
    """Log an unauthorized attempt and raise HTTP 403."""
    log_security_event("unauthorized_access", description)
    abort(403)
