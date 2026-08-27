"""The HTTP edge of authorisation.

`permissions.py` holds the policy and knows nothing about requests. This
file is the only place that turns a decision into a status code, the same
way the projects router turns `ingestion.LimitExceeded` into a 413.

Identity comes from an `X-User` header naming a user in the users table.
That is the seam: a real login system replaces `identify()` and nothing
else in the project changes.

**This is not authentication and does not pretend to be.** A header can be
set by anyone, so it establishes which role is being exercised, not who is
exercising it. Saying so plainly here is the honest version; a header
called `Authorization` carrying the same unverified string would look like
security and provide none.
"""

import re
from uuid import uuid4

from fastapi import Cookie, Depends, Header, HTTPException, Response, status

import permissions
import storage
from permissions import User

# The cookie carrying one anonymous visitor's identity.
GUEST_COOKIE = "compass_guest"

# A month. Long enough that a guest coming back next week still finds their
# own history; short enough that abandoned identities do not accumulate.
GUEST_COOKIE_MAX_AGE = 60 * 60 * 24 * 30

# 32 hex characters, and nothing else. The token becomes part of an owner
# string that is stored and compared, so a client must not be able to put
# arbitrary text there.
GUEST_TOKEN = re.compile(r"^[0-9a-f]{32}$")


def identify(
    response: Response,
    x_user: str | None = Header(default=None),
    compass_guest: str | None = Cookie(default=None),
) -> User:
    """Resolve the caller into a User.

    A registered name in `X-User` wins. Anyone else is a guest — but a guest
    with an identity of their own, not one shared with every other visitor.

    An unknown name is deliberately NOT an error: this build has no
    registration, so refusing unknown names would make the API unusable
    before any user exists, and would leak which names are registered.

    **Why the server issues the guest token rather than the client.**
    Two visitors generating their own could collide, which is the exact bug
    this replaces. The server mints it once and sets it as an HttpOnly
    cookie, so it is unguessable and out of reach of page scripts.

    This is still not authentication. A guest who copies someone else's
    cookie becomes them, exactly as anyone may claim any `X-User`. It stops
    strangers sharing a pool BY DEFAULT, which was the real problem; it does
    not defend against someone deliberately impersonating another visitor.
    """
    if x_user:
        record = storage.get_user(x_user.strip())
        if record is not None:
            return User(record["name"], record["role"])

    token = compass_guest if compass_guest and GUEST_TOKEN.match(compass_guest) else None
    if token is None:
        token = uuid4().hex
        response.set_cookie(
            GUEST_COOKIE,
            token,
            max_age=GUEST_COOKIE_MAX_AGE,
            httponly=True,   # a page script cannot read or steal it
            samesite="lax",
        )

    return User(permissions.guest_name(token), permissions.GUEST)


CurrentUser = Depends(identify)


def deny(error: permissions.PermissionDenied) -> HTTPException:
    """Turn a policy refusal into a 403.

    403 and not 401: the request was understood and the role is known, it
    simply may not do this. A 401 would invite the client to authenticate,
    which would be a lie in a build with nothing to authenticate against.
    """
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(error))


def require(user: User, permission: str) -> None:
    """Enforce a permission, or raise the matching HTTP error."""
    try:
        permissions.require(user, permission)
    except permissions.PermissionDenied as error:
        raise deny(error) from error


def require_readable(user: User, record: dict, what: str) -> None:
    """Enforce read access to one record.

    A record the user may not read answers 404, not 403. Returning 403 would
    confirm that the id exists and belongs to somebody else, which turns the
    endpoint into an oracle for enumerating other people's submissions. The
    same answer as for an id that was never issued gives nothing away.
    """
    if not permissions.may_read(user, record):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"{what} not found"
        )
