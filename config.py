"""Application configuration.

Secrets are loaded from environment variables (or a local .env file).
Never commit real secrets to source control.
"""

import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    """Base configuration shared by all environments."""

    # Core
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-insecure-key-change-me")
    JSON_SORT_KEYS = False

    # Database (SQLite lives inside the instance folder)
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or (
        f"sqlite:///{(BASE_DIR / 'instance' / 'secure_file_sharing.db').as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # Uploaded / encrypted file storage (outside static and outside the web root)
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER") or str(
        BASE_DIR / "instance" / "secure_files"
    )
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 25 * 1024 * 1024))
    ALLOWED_EXTENSIONS = frozenset(
        {"pdf", "doc", "docx", "xls", "xlsx", "txt", "csv", "jpg", "jpeg", "png", "zip"}
    )

    # AES-256-GCM key: URL-safe base64 encoded 32 random bytes
    FILE_ENCRYPTION_KEY = os.environ.get("FILE_ENCRYPTION_KEY", "")

    # Sessions / cookies
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _as_bool(os.environ.get("SESSION_COOKIE_SECURE"), False)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = _as_bool(os.environ.get("SESSION_COOKIE_SECURE"), False)
    REMEMBER_COOKIE_DURATION = timedelta(days=14)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_REFRESH_EACH_REQUEST = True

    # CSRF
    WTF_CSRF_TIME_LIMIT = None
    WTF_CSRF_SSL_STRICT = False

    # Pagination
    ITEMS_PER_PAGE = 10
