"""Endpoints for the "users" domain.

Managing who exists and what role they hold. Every write here needs the
MANAGE_USERS permission, which only an admin has.

There is a bootstrapping problem worth naming rather than hiding: with an
empty users table, nobody is an admin, so nobody can create the first one.
It is solved by `COMPASS_BOOTSTRAP_ADMIN` — a name from the environment that
is treated as an admin even when the table is empty. It stops working the
moment a real admin exists, so it cannot be left switched on by accident.

Every other approach to first-admin is worse: a hardcoded default account is
a permanent backdoor, and an open "create the first user" endpoint is a race
anybody on the network can win.
"""

import os

from fastapi import APIRouter, Header, HTTPException, status

import permissions
import storage
from permissions import User
from routers import security
from schemas import ErrorResponse, UserIn, UserOut, WhoAmI

router = APIRouter(prefix="/users", tags=["Users"])


def _bootstrap_name() -> str | None:
    name = os.environ.get("COMPASS_BOOTSTRAP_ADMIN")
    return name.strip() if name and name.strip() else None


def _may_manage(user: User, claimed: str | None) -> bool:
    """Whether this caller may change users.

    True for a real admin, and for the bootstrap name only while no user
    exists at all. The second condition is what makes it self-closing.

    `claimed` is the raw header, not the resolved user. It has to be:
    `identify()` turns an unregistered name into the anonymous guest, so by
    the time we hold a User the bootstrap name has already been replaced —
    and before the first admin exists, the bootstrap name is by definition
    unregistered.
    """
    if user.can(permissions.MANAGE_USERS):
        return True
    bootstrap = _bootstrap_name()
    if not bootstrap or not claimed:
        return False
    return claimed.strip() == bootstrap and not storage.get_all_users()


def _require_manage(user: User, claimed: str | None) -> None:
    if not _may_manage(user, claimed):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(permissions.PermissionDenied(permissions.MANAGE_USERS, user.role)),
        )


@router.get(
    "/me",
    response_model=WhoAmI,
    summary="Who am I, and what may I do",
)
def whoami(user: User = security.CurrentUser):
    """Return the caller's identity and full permission set.

    Open to everyone, including guests: a client needs this to render only
    the actions it is allowed to take, rather than offering buttons that
    answer 403. It reveals nothing the caller could not discover by trying.
    """
    return {
        "name": user.name,
        "role": user.role,
        "permissions": sorted(permissions.ROLE_PERMISSIONS.get(user.role, [])),
    }


@router.get(
    "",
    response_model=list[UserOut],
    summary="List users",
    responses={status.HTTP_403_FORBIDDEN: {"model": ErrorResponse}},
)
def list_users(
    user: User = security.CurrentUser, x_user: str | None = Header(default=None)
):
    _require_manage(user, x_user)
    return storage.get_all_users()


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=UserOut,
    summary="Create or update a user",
    responses={
        status.HTTP_403_FORBIDDEN: {"model": ErrorResponse},
        status.HTTP_422_UNPROCESSABLE_CONTENT: {"model": ErrorResponse},
    },
)
def create_user(
    payload: UserIn,
    user: User = security.CurrentUser,
    x_user: str | None = Header(default=None),
):
    _require_manage(user, x_user)

    if payload.role not in permissions.ROLES:
        # A role outside the matrix would hold no permissions at all, so the
        # user would exist and be able to do nothing — a confusing outcome
        # to debug. Refusing names the mistake instead.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Unknown role '{payload.role}'. Valid roles: "
            + ", ".join(permissions.ROLES),
        )

    return storage.save_user(payload.name, payload.role)


@router.delete(
    "/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a user",
    responses={
        status.HTTP_403_FORBIDDEN: {"model": ErrorResponse},
        status.HTTP_404_NOT_FOUND: {"model": ErrorResponse},
    },
)
def delete_user(
    name: str,
    user: User = security.CurrentUser,
    x_user: str | None = Header(default=None),
):
    _require_manage(user, x_user)

    if name == user.name:
        # Removing your own admin rights can leave a system with no admin
        # and no way back in.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="You cannot remove your own account.",
        )

    if not storage.delete_user(name):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
