"""Test-wide safety net: no API key, no network, no cost.

Every test in this suite runs offline. That is not a happy accident — it is
enforced here, because a suite that quietly starts spending money the day a
developer adds a key to `.env` is a suite nobody can trust to run.

Two guards, both session-wide:

1. **The API key is removed** for the whole run. Any code path that would
   have built a real client gets `None` instead and degrades, exactly as it
   does on a machine with no key.

2. **Outbound network is blocked.** Connecting anywhere other than loopback
   raises immediately, with a message saying which test did it. A test that
   accidentally reaches the internet fails loudly instead of passing slowly
   and charging for the privilege.

Neither guard affects subprocesses, so Semgrep still runs normally — it needs
no network anyway, since the rules are local and telemetry is off.
"""

import shutil
import socket
import tempfile
from pathlib import Path

import pytest

REAL_CONNECT = socket.socket.connect
REAL_CONNECT_EX = socket.socket.connect_ex

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class NetworkUsedInTests(RuntimeError):
    """Raised when a test tries to reach the network."""


def _is_loopback(address) -> bool:
    if isinstance(address, tuple) and address:
        return str(address[0]) in LOOPBACK
    return False


@pytest.fixture(autouse=True, scope="session")
def offline_and_free():
    """Remove the API key and block the network for the whole session."""
    with pytest.MonkeyPatch.context() as patch:
        # Set to empty rather than delete. Deleting is not enough: settings.py
        # calls load_dotenv() when it is first imported, which happens DURING
        # the run, and a `.env` on disk would put the key straight back.
        #
        # load_dotenv never overwrites a variable that already exists, so an
        # empty string blocks it — and settings.anthropic_api_key() returns
        # None for an empty value, which is precisely why it is written
        # `return key or None`.
        #
        # This hole was found by running the suite with a real .env present.
        patch.setenv("ANTHROPIC_API_KEY", "")

        # Import settings NOW, while the variable is empty, so load_dotenv
        # runs exactly once and finds the value already set. Without this the
        # first import happens inside whichever test touches the Claude layer
        # first — and if that test deleted the variable, .env would refill it.
        # Pinning the import here makes the guard independent of test order.
        import settings  # noqa: F401

        def guarded_connect(self, address, *args, **kwargs):
            if _is_loopback(address):
                return REAL_CONNECT(self, address, *args, **kwargs)
            raise NetworkUsedInTests(
                f"A test tried to reach {address}. The suite is offline by "
                "design: inject a fake client instead of calling the real API."
            )

        def guarded_connect_ex(self, address, *args, **kwargs):
            if _is_loopback(address):
                return REAL_CONNECT_EX(self, address, *args, **kwargs)
            raise NetworkUsedInTests(f"A test tried to reach {address}.")

        patch.setattr(socket.socket, "connect", guarded_connect)
        patch.setattr(socket.socket, "connect_ex", guarded_connect_ex)

        # Third guard, added when storage moved to SQLite: the suite must
        # never write to the real database. Without this, running the tests
        # would empty a developer's own analysis history — clear() is
        # autoused by several test modules, and it does exactly what it says.
        #
        # A temporary FILE, not ":memory:": storage opens one connection per
        # call, and every in-memory connection would be a separate empty
        # database.
        database = tempfile.mkdtemp(prefix="compass-tests-") + "/test.db"
        patch.setenv("COMPASS_DB", database)

        # A signing secret for the suite. Long enough to satisfy the
        # 32-byte minimum RFC 7518 requires for HS256 — the same check
        # the application enforces, so the tests cannot pass with a key
        # that production would refuse.
        patch.setenv(
            "COMPASS_JWT_SECRET",
            "test-only-signing-secret-never-used-outside-the-suite-0123456789",
        )

        yield

        shutil.rmtree(Path(database).parent, ignore_errors=True)
