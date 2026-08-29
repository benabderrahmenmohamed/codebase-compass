"""Endpoints for the "users" domain.

Managing who exists and what role they hold. Every write here needs the
MANAGE_USERS permission, which only an admin has.

There is a bootstrapping problem worth naming rather than hiding: with an
empty users table, nobody is an admin, so nobody can create the first one.

It is solved by a one-time shared secret in `COMPASS_BOOTSTRAP_TOKEN`,
presented in an `X-Bootstrap-Token` header. It stops working the moment any
user exists, so it cannot be left switched on by accident.

This used to be a NAME compared against the `X-User` header. That was
acceptable while `X-User` was the identity mechanism, and became a hole the
moment real authentication arrived: an unauthenticated caller who guessed
the name could still create an administrator. A secret is the right shape
for this — it is something you know, not something you claim to be — and
it is compared in constant time so the comparison itself does not leak the
value one character at a time.

Every other approach to first-admin is worse: a hardcoded default account is
a permanent backdoor, and an open "create the first user" endpoint is a race
anybody on the network can win.
"""

import os
import secrets

from fastapi import APIRouter, Header, HTTPException, status

import passwords
import permissions
import storage
from permissions import User
from routers import security
from schemas import ErrorResponse, UserIn, UserOut, WhoAmI

router = APIRouter(prefix="/users", tags=["Users"])


# Short enough to type, long enough not to be guessed in the window
# between deploying and creating the first account.
MIN_BOOTSTRAP_TOKEN_LENGTH = 16


def _bootstrap_token() -> str | None:
    token = os.environ.get("COMPASS_BOOTSTRAP_TOKEN")
    if not token or len(token.strip()) < MIN_BOOTSTRAP_TOKEN_LENGTH:
        # A short secret is treated as no secret rather than as a weak one.
        # Failing closed here beats accepting a four-character token that
        # someone set "just for testing".
        return None
    return token.strip()


def _may_manage(user: User, presented: str | None) -> bool:
    """Whether this caller may change users.

    True for an authenticated admin, and for a correct bootstrap secret
    while no user exists at all. The second condition is what makes it
    self-closing: creating the first account switches it off.
    """
    if user.can(permissions.MANAGE_USERS):
        return True

    expected = _bootstrap_token()
    if not expected or not presented:
        return False
    if storage.get_all_users():
        return False

    # Constant time. A plain == returns as soon as two characters differ,
    # so an attacker measuring the response can recover the secret one
    # character at a time rather than guessing the whole thing.
    return secrets.compare_digest(presented.strip(), expected)


def _require_manage(user: User, presented: str | None) -> None:
    if not _may_manage(user, presented):
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
    user: User = security.CurrentUser, x_bootstrap_token: str | None = Header(default=None)
):
    _require_manage(user, x_bootstrap_token)
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
    x_bootstrap_token: str | None = Header(default=None),
):
    _require_manage(user, x_bootstrap_token)

    if payload.role not in permissions.ROLES:
        # A role outside the matrix would hold no permissions at all, so the
        # user would exist and be able to do nothing — a confusing outcome
        # to debug. Refusing names the mistake instead.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Unknown role '{payload.role}'. Valid roles: "
            + ", ".join(permissions.ROLES),
        )

    password_hash = None
    if payload.password is not None:
        try:
            password_hash = passwords.hash_password(payload.password)
        except ValueError as error:
            # passwords.py raises a domain error; this is where it becomes
            # a status code.
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)
            ) from error

    return storage.save_user(payload.name, payload.role, password_hash)


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
    x_bootstrap_token: str | None = Header(default=None),
):
    _require_manage(user, x_bootstrap_token)

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
