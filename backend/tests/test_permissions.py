"""Roles and permissions.

Two halves. The first tests the matrix as pure policy — no HTTP, no
requests, just "may this role do this?". The second drives it through the
API, because a matrix nobody enforces is a document, not a control.
"""

import pytest

import permissions
from permissions import ADMIN, DEVELOPER, GUEST, LEAD, User


# --------------------------------------------------------------------------
# The matrix itself
# --------------------------------------------------------------------------


def test_every_role_appears_in_the_matrix():
    """A role missing from the matrix would hold no permissions and be
    silently useless."""
    assert set(permissions.ROLE_PERMISSIONS) == set(permissions.ROLES)


def test_the_matrix_grants_only_known_permissions():
    """A typo would grant a permission nothing ever checks."""
    for role, granted in permissions.ROLE_PERMISSIONS.items():
        unknown = granted - set(permissions.PERMISSIONS)
        assert not unknown, f"{role} grants unknown permission(s): {unknown}"


@pytest.mark.parametrize(
    "role,permission,allowed",
    [
        # Everyone can submit and read what they own.
        (GUEST, permissions.SUBMIT_SNIPPET, True),
        (GUEST, permissions.SUBMIT_PROJECT, True),
        (GUEST, permissions.READ_OWN, True),
        # The paid layer is the line. This is the cost control.
        (GUEST, permissions.USE_LLM, False),
        (DEVELOPER, permissions.USE_LLM, True),
        (LEAD, permissions.USE_LLM, True),
        (ADMIN, permissions.USE_LLM, True),
        # Seeing everybody's submissions starts at lead.
        (GUEST, permissions.READ_ALL, False),
        (DEVELOPER, permissions.READ_ALL, False),
        (LEAD, permissions.READ_ALL, True),
        (ADMIN, permissions.READ_ALL, True),
        # Administration is admin only.
        (LEAD, permissions.MANAGE_USERS, False),
        (ADMIN, permissions.MANAGE_USERS, True),
        (LEAD, permissions.VIEW_COSTS, False),
        (ADMIN, permissions.VIEW_COSTS, True),
    ],
)
def test_the_matrix_says_what_it_should(role, permission, allowed):
    assert User("someone", role).can(permission) is allowed


def test_an_unknown_role_can_do_nothing():
    """Fail closed. An unrecognised role must not inherit anything."""
    stranger = User("mallory", "superuser")
    for permission in permissions.PERMISSIONS:
        assert stranger.can(permission) is False


def test_require_raises_for_a_denied_permission():
    with pytest.raises(permissions.PermissionDenied):
        permissions.require(User("g", GUEST), permissions.USE_LLM)


def test_require_is_silent_when_allowed():
    permissions.require(User("d", DEVELOPER), permissions.USE_LLM)


def test_the_denial_names_the_role_and_the_action():
    """A 403 saying only "forbidden" costs someone an afternoon."""
    error = permissions.PermissionDenied(permissions.USE_LLM, GUEST)
    assert "guest" in str(error)
    assert "use llm" in str(error)


# --------------------------------------------------------------------------
# Ownership
# --------------------------------------------------------------------------


def test_a_developer_sees_only_their_own_records():
    records = [{"owner": "alice"}, {"owner": "bob"}]
    assert permissions.visible_to(User("alice", DEVELOPER), records) == [{"owner": "alice"}]


def test_a_lead_sees_everything():
    records = [{"owner": "alice"}, {"owner": "bob"}]
    assert permissions.visible_to(User("carol", LEAD), records) == records


def test_a_record_with_no_owner_belongs_to_the_anonymous_pool():
    """Records stored before ownership existed must not vanish, and must not
    become everybody's."""
    records = [{"no": "owner"}]
    assert permissions.visible_to(permissions.ANONYMOUS_USER, records) == records
    assert permissions.visible_to(User("alice", DEVELOPER), records) == []


def test_may_read_matches_visible_to():
    record = {"owner": "alice"}
    assert permissions.may_read(User("alice", DEVELOPER), record) is True
    assert permissions.may_read(User("bob", DEVELOPER), record) is False
    assert permissions.may_read(User("carol", LEAD), record) is True


# --------------------------------------------------------------------------
# The paid layer
# --------------------------------------------------------------------------


def test_a_guest_cannot_trigger_the_paid_layer():
    assert permissions.llm_allowed(permissions.ANONYMOUS_USER, True) is False


def test_a_developer_can():
    assert permissions.llm_allowed(User("d", DEVELOPER), True) is True


def test_asking_not_to_use_it_is_still_honoured():
    assert permissions.llm_allowed(User("d", DEVELOPER), False) is False
