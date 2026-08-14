"""A small, well-behaved module: the control sample."""

from datetime import datetime, timezone


def build_greeting(first_name: str, last_name: str) -> str:
    """Return a greeting for a person."""
    return f"Hello {first_name} {last_name}"


def current_timestamp() -> str:
    """Return the current time in UTC, ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


def initials(first_name: str, last_name: str) -> str:
    """Return the person's initials in upper case."""
    return f"{first_name[:1]}{last_name[:1]}".upper()
