"""Password hashing.

Separated from tokens (`tokens.py`) and from policy (`permissions.py`)
because these are three different problems that get confused with one
another. This file answers exactly one question: does this password match
the stored hash?

**Why Argon2id.**
It is OWASP's first recommendation for new applications, and it won the
Password Hashing Competition. The `id` variant is the one to use: Argon2d
resists GPU cracking but leaks timing through data-dependent memory access,
Argon2i resists side channels but is weaker against GPUs, and Argon2id runs
the first pass as `i` and the rest as `d`, taking both defences.

bcrypt was the obvious alternative and was rejected for a specific reason:
it silently truncates at 72 bytes. A user whose password is longer than
that has the tail ignored, and — worse — two different long passwords
sharing a 72-byte prefix become the same password. Nothing warns anybody.

**Why the cost parameters are not the library defaults left unexamined.**
Argon2 is deliberately expensive in MEMORY, not just time, because memory
is what makes GPU and ASIC attacks uneconomic. The values below are
argon2-cffi's defaults, which follow the RFC 9106 second recommended
option: 64 MiB, three passes, four lanes. They are stated here explicitly
rather than inherited silently, so that raising them later is a visible
decision — and so a reader can see that the question was asked.

**On salts and pepper.**
Argon2 generates a random salt per password and stores it inside the
returned string, so there is no salt column and no way to forget one. A
pepper — a secret mixed in from configuration — is deliberately not
used: it protects only against an attacker who reads the database but not
the application config, and it introduces a key that, if lost, invalidates
every password in the system.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# RFC 9106's second recommended configuration, stated rather than inherited.
#   memory_cost : 64 MiB per hash — what makes parallel cracking expensive
#   time_cost   : three passes over that memory
#   parallelism : four lanes
MEMORY_COST_KIB = 65536
TIME_COST = 3
PARALLELISM = 4

# Argon2 has no truncation limit, but an unbounded password is an unbounded
# amount of work for the server: a megabyte-long password would be a cheap
# way to exhaust CPU. This is a denial-of-service bound, not a security one.
MAX_PASSWORD_LENGTH = 1024

# Rejecting short passwords is the one composition rule worth keeping. NIST
# SP 800-63B advises AGAINST forced character classes — they push people to
# "Password1!" — but length is the property that actually matters.
MIN_PASSWORD_LENGTH = 10

_hasher = PasswordHasher(
    memory_cost=MEMORY_COST_KIB,
    time_cost=TIME_COST,
    parallelism=PARALLELISM,
)

# A real Argon2id hash of a value nobody can supply, used to spend the same
# CPU time when the account does not exist. Computed once at import: doing
# it per request would itself be a timing signal, and would be wasteful.
#
# Without this, a login for a real user is slow (a hash is verified) and a
# login for an unknown user is instant (nothing to verify). That difference
# is measurable over the network and turns the login endpoint into a way to
# enumerate valid usernames.
_DUMMY_HASH = _hasher.hash("argon2id-timing-equaliser-not-a-real-password")


class PasswordTooShort(ValueError):
    """Domain error. The router turns it into a 422."""

    def __init__(self, minimum: int = MIN_PASSWORD_LENGTH):
        self.minimum = minimum
        super().__init__(
            f"A password must be at least {minimum} characters. "
            "Length matters more than mixing symbols in."
        )


class PasswordTooLong(ValueError):
    def __init__(self, maximum: int = MAX_PASSWORD_LENGTH):
        self.maximum = maximum
        super().__init__(f"A password may be at most {maximum} characters.")


def validate(password: str) -> None:
    """Check a password against the composition rules, or raise."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordTooShort()
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordTooLong()


def hash_password(password: str) -> str:
    """Hash a password for storage. Validates first.

    The returned string carries the algorithm, its parameters and the salt,
    which is what allows `needs_rehash` to detect a hash made with weaker
    settings later.
    """
    validate(password)
    return _hasher.hash(password)


def verify(stored_hash: str | None, password: str) -> bool:
    """Whether the password matches. Never raises.

    `stored_hash` may be None — a user created before passwords existed,
    or one an administrator added without setting one. Such an account
    cannot log in, and the dummy hash is still verified so that the answer
    takes the same time as a real failure.
    """
    if not stored_hash:
        _spend_equivalent_time()
        return False

    try:
        return _hasher.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
    except InvalidHashError:
        # A corrupted or hand-edited hash. Treated as "no match" rather than
        # crashing the endpoint, and it fails closed.
        return False


def _spend_equivalent_time() -> None:
    """Verify a throwaway hash so a missing account costs the same as a
    wrong password."""
    try:
        _hasher.verify(_DUMMY_HASH, "not the password")
    except VerifyMismatchError:
        pass


def needs_rehash(stored_hash: str) -> bool:
    """Whether this hash was made with weaker parameters than we now use.

    Cost parameters should rise as hardware gets faster. This is what lets
    that happen without asking anybody to change their password: on the next
    successful login the plaintext is briefly in hand, so it can be rehashed
    at the current settings.
    """
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True
