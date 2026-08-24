"""Roles and permissions: who may do what.

This is AUTHORISATION, not authentication. It answers "is this role allowed
to do this?" and never "is this person who they claim to be?" The two are
routinely confused and are different problems: the brief asks for
roles/permissions, and a password system is neither required by it nor free
to get right.

So identity arrives from outside this module and is taken at face value. In
this build it is a header naming a user. That is deliberately a seam: real
login replaces `identify()` in one place and every rule below is unchanged,
exactly as SQLite replaced the in-memory store without touching a caller.

**This file knows nothing about HTTP.** It returns a decision; the router
turns a denial into 401 or 403. Same rule as ingestion raising
LimitExceeded rather than a 413.

Two permissions carry weight beyond tidiness:

* USE_LLM is what stops an anonymous visitor spending the owner's Anthropic
  credit. A measured run costs about $0.22, so "guests get the deterministic
  report" is not a courtesy tier — it is the cost control, and it lives here
  rather than in a rate limiter bolted on later.

* READ_ALL is the difference between seeing your own submissions and seeing
  everybody's. Submitted code is often not the submitter's to share.
"""

from typing import NamedTuple

# --------------------------------------------------------------------------
# Roles
# --------------------------------------------------------------------------

GUEST = "guest"
DEVELOPER = "developer"
LEAD = "lead"
ADMIN = "admin"

ROLES = (GUEST, DEVELOPER, LEAD, ADMIN)

# --------------------------------------------------------------------------
# Permissions
# --------------------------------------------------------------------------

SUBMIT_SNIPPET = "submit_snippet"
SUBMIT_PROJECT = "submit_project"
USE_LLM = "use_llm"
READ_OWN = "read_own"
READ_ALL = "read_all"
MANAGE_USERS = "manage_users"
VIEW_COSTS = "view_costs"

PERMISSIONS = (
    SUBMIT_SNIPPET,
    SUBMIT_PROJECT,
    USE_LLM,
    READ_OWN,
    READ_ALL,
    MANAGE_USERS,
    VIEW_COSTS,
)

# The matrix, written out in full rather than derived from a hierarchy.
#
# A hierarchy ("lead inherits developer") reads well and hides exactly the
# question a reviewer needs answered: what, precisely, can this role do?
# Spelling it out means the answer is read rather than computed, and a
# mistake is visible on the page instead of buried in an inheritance chain.
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    GUEST: frozenset({SUBMIT_SNIPPET, SUBMIT_PROJECT, READ_OWN}),
    DEVELOPER: frozenset({SUBMIT_SNIPPET, SUBMIT_PROJECT, USE_LLM, READ_OWN}),
    LEAD: frozenset({SUBMIT_SNIPPET, SUBMIT_PROJECT, USE_LLM, READ_OWN, READ_ALL}),
    ADMIN: frozenset(
        {
            SUBMIT_SNIPPET,
            SUBMIT_PROJECT,
            USE_LLM,
            READ_OWN,
            READ_ALL,
            MANAGE_USERS,
            VIEW_COSTS,
        }
    ),
}

# Guests are anonymous, so there is nobody to bill and nobody to blame.
# They get everything the deterministic pipeline produces — map, findings,
# scores, grade — and never the paid layer.
DEFAULT_ROLE = GUEST

# The name recorded as the owner of anything a guest submits. Guests share
# it, so a guest can see guest submissions; that is the honest consequence
# of not identifying them, and it is why guests should not be given READ_ALL.
ANONYMOUS = "anonymous"


class User(NamedTuple):
    """Who is acting, and as what."""

    name: str
    role: str

    @property
    def is_guest(self) -> bool:
        return self.role == GUEST

    def can(self, permission: str) -> bool:
        return permission in ROLE_PERMISSIONS.get(self.role, frozenset())


ANONYMOUS_USER = User(ANONYMOUS, GUEST)


class PermissionDenied(Exception):
    """The role is known and not allowed to do this.

    A domain exception, like ingestion.LimitExceeded. The router turns it
    into a 403; nothing here knows that number exists.
    """

    def __init__(self, permission: str, role: str):
        self.permission = permission
        self.role = role
        super().__init__(f"Role '{role}' may not {permission.replace('_', ' ')}.")


def require(user: User, permission: str) -> None:
    """Raise unless the user holds the permission."""
    if not user.can(permission):
        raise PermissionDenied(permission, user.role)


def visible_to(user: User, records: list[dict], owner_key: str = "owner") -> list[dict]:
    """Filter a list down to what this user may see.

    READ_ALL sees everything. Everyone else sees what they own — and a
    record stored before ownership existed has no owner, so it is treated as
    the anonymous pool rather than hidden from everybody or shown to
    everybody.
    """
    if user.can(READ_ALL):
        return records
    return [
        record
        for record in records
        if record.get(owner_key, ANONYMOUS) == user.name
    ]


def may_read(user: User, record: dict, owner_key: str = "owner") -> bool:
    """Whether one record is readable by this user."""
    if user.can(READ_ALL):
        return True
    return record.get(owner_key, ANONYMOUS) == user.name


def llm_allowed(user: User, requested: bool) -> bool:
    """Whether the paid layer may run for this request.

    A guest asking for it is not an error — the deterministic report is
    still produced and the report says the explanations are missing, which
    is the same degradation as having no API key. Refusing the whole request
    would punish curiosity; silently charging for it would be worse.
    """
    return bool(requested) and user.can(USE_LLM)
