"""Time helpers.

The application stores naive UTC timestamps for consistent SQLite behaviour.
"""

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return the current UTC time as a naive datetime (no deprecation warnings)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
