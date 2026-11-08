"""SQLAlchemy database models for the Secure File Sharing System."""

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db
from app.timeutils import utcnow


ROLE_ADMIN = "admin"
ROLE_USER = "user"

PERMISSION_VIEW = "view"
PERMISSION_DOWNLOAD = "download"
PERMISSION_TYPES = (PERMISSION_VIEW, PERMISSION_DOWNLOAD)

PERMISSION_LABELS = {
    PERMISSION_VIEW: "View only",
    PERMISSION_DOWNLOAD: "Download",
}

ACTIVITY_ACTIONS = [
    "registration",
    "login",
    "login_failed",
    "logout",
    "upload",
    "download",
    "preview",
    "delete",
    "share",
    "permission_change",
    "revoke",
    "unauthorized_access",
    "account_status",
    "profile_update",
    "password_change",
]

SECURITY_EVENT_TYPES = [
    "login_failed",
    "unauthorized_access",
    "decryption_failure",
    "file_validation_failure",
    "permission_change",
    "account_activated",
    "account_deactivated",
    "password_change",
]


class User(UserMixin, db.Model):
    """Registered application user."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(60), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=ROLE_USER)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)

    files = db.relationship(
        "File",
        back_populates="owner",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    permissions_granted = db.relationship(
        "FilePermission",
        foreign_keys="FilePermission.owner_id",
        back_populates="owner",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    permissions_received = db.relationship(
        "FilePermission",
        foreign_keys="FilePermission.shared_with_id",
        back_populates="shared_with",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    activity_logs = db.relationship(
        "ActivityLog",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    security_events = db.relationship(
        "SecurityEvent",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    @property
    def initials(self) -> str:
        parts = [part for part in self.full_name.split() if part]
        if not parts:
            return self.username[:2].upper()
        if len(parts) == 1:
            return parts[0][:2].upper()
        return (parts[0][0] + parts[-1][0]).upper()

    def set_password(self, password: str) -> None:
        """Store a salted Werkzeug password hash (never plaintext)."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def get_id(self) -> str:
        return str(self.id)

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<User {self.username}>"


class File(db.Model):
    """Metadata for a file stored encrypted on disk."""

    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    mime_type = db.Column(db.String(120), nullable=False)
    encryption_status = db.Column(db.String(40), nullable=False, default="AES-256-GCM")
    uploaded_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    owner = db.relationship("User", back_populates="files")
    permissions = db.relationship(
        "FilePermission",
        back_populates="file",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    @property
    def extension(self) -> str:
        if "." not in self.original_filename:
            return ""
        return self.original_filename.rsplit(".", 1)[1].lower()

    @property
    def is_encrypted(self) -> bool:
        return self.encryption_status == "AES-256-GCM"

    @property
    def active_permissions_count(self) -> int:
        return self.permissions.filter_by(is_active=True).count()

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<File {self.original_filename}>"


class FilePermission(db.Model):
    """Access grant from a file owner to another registered user."""

    __tablename__ = "file_permissions"
    __table_args__ = (
        db.UniqueConstraint("file_id", "shared_with_id", name="uq_file_recipient"),
    )

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(
        db.Integer, db.ForeignKey("files.id", ondelete="CASCADE"), nullable=False, index=True
    )
    owner_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    shared_with_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    permission_type = db.Column(db.String(20), nullable=False, default=PERMISSION_VIEW)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime, nullable=False, default=utcnow, onupdate=utcnow
    )

    file = db.relationship("File", back_populates="permissions")
    owner = db.relationship(
        "User", foreign_keys=[owner_id], back_populates="permissions_granted"
    )
    shared_with = db.relationship(
        "User", foreign_keys=[shared_with_id], back_populates="permissions_received"
    )

    @property
    def permission_label(self) -> str:
        return PERMISSION_LABELS.get(self.permission_type, self.permission_type)

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<FilePermission file={self.file_id} user={self.shared_with_id}>"


class ActivityLog(db.Model):
    """Audit trail of user and file activity."""

    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    action = db.Column(db.String(50), nullable=False, index=True)
    description = db.Column(db.String(500), nullable=False)
    file_id = db.Column(db.Integer, nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    user = db.relationship("User", back_populates="activity_logs")

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<ActivityLog {self.action}>"


class SecurityEvent(db.Model):
    """Security-focused event stream for monitoring and alerts."""

    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    event_type = db.Column(db.String(50), nullable=False, index=True)
    description = db.Column(db.String(500), nullable=False)
    ip_address = db.Column(db.String(64), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    user = db.relationship("User", back_populates="security_events")

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<SecurityEvent {self.event_type}>"
