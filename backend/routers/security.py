"""The HTTP edge of identity and authorisation.

`tokens.py` verifies signatures, `permissions.py` holds the policy, and
neither knows what a status code is. This file is where a rejected token
becomes a 401 and a refused action becomes a 403 — the same arrangement as
`ingestion.LimitExceeded` becoming a 413.

**401 and 403 are not interchangeable.**
401 means "I do not know who you are": the credentials were absent, expired
or forged, and presenting better ones would help. 403 means "I know exactly
who you are and you may not do this": presenting the same credentials again
will never help. Returning 403 for an expired token sends a client to a
support desk instead of the login page.

**The X-User header is gone.**
It used to name a user and was believed at face value. That was honest while
there was nothing to authenticate against, and it becomes an authentication
bypass the moment there is: an attacker who sent `X-User: root` would have
been an administrator. Leaving it as a fallback "for development" is how
such holes reach production, so it was removed rather than deprecated, and
a test asserts it no longer works.
"""

import re
from uuid import uuid4

from fastapi import Cookie, Depends, Header, HTTPException, Response, status

import permissions
import storage
import tokens
from permissions import User

# The cookie carrying one anonymous visitor's identity. Guests are not
# authenticated — there is nothing to authenticate — but they are told
# apart, so one visitor's submissions are not visible to the next.
GUEST_COOKIE = "compass_guest"

# A month. Long enough that a guest returning next week still finds their
# own history; short enough that abandoned identities do not accumulate.
GUEST_COOKIE_MAX_AGE = 60 * 60 * 24 * 30

# 32 hex characters and nothing else. The token becomes part of an owner
# string that is stored and compared, so a client must not be able to put
# arbitrary text there.
GUEST_TOKEN = re.compile(r"^[0-9a-f]{32}$")

BEARER = "bearer"


def _unauthorised(reason: str, message: str) -> HTTPException:
    """A 401 that says which of the several possible problems occurred.

    The reason is echoed in a header rather than only in the body so that a
    client can react — refresh, re-authenticate, or surface a configuration
    error — without parsing prose.
    """
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=message,
        headers={"WWW-Authenticate": f'Bearer error="{reason}"'},
    )


def _from_bearer(authorization: str) -> User:
    """Turn an Authorization header into a User, or raise 401."""
    scheme, _, credential = authorization.partition(" ")
    if scheme.lower() != BEARER or not credential.strip():
        raise _unauthorised(
            "invalid_request",
            "Authorization must be 'Bearer <token>'.",
        )

    try:
        claims = tokens.verify(credential.strip())
    except tokens.TokenError as error:
        if error.reason in ("no_secret", "weak_secret"):
            # A server misconfiguration, not a bad credential. 500 rather
            # than 401: no token the client could present would work, and
            # telling them to sign in again would be a false instruction.
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(error)
            ) from error
        raise _unauthorised(error.reason, str(error)) from error

    # The role travels inside the token so authorising a request needs no
    # database read. The cost is that a role changed since the token was
    # issued does not reach it — which is why tokens are short-lived.
    #
    # Deletion is different and is checked: a removed account must stop
    # working immediately, because that is the action taken when someone
    # leaves or an account is compromised.
    record = storage.get_user(claims.name)
    if record is None:
        raise _unauthorised(
            "revoked", "This account no longer exists. Sign in again."
        )

    return User(record["name"], record["role"])


def identify(
    response: Response,
    authorization: str | None = Header(default=None),
    compass_guest: str | None = Cookie(default=None),
) -> User:
    """Resolve the caller into a User.

    A valid bearer token wins. Anything else is a guest — with an identity
    of their own, not one shared with every other visitor.

    A guest is not "a failed login". The tool is deliberately usable without
    an account: the deterministic report costs nothing to produce and needs
    nobody's permission. What a guest cannot do is spend the owner's API
    credit or read another person's submissions.
    """
    if authorization:
        return _from_bearer(authorization)

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

    403 and not 401: the request was understood and the identity is known,
    it simply may not do this. A 401 would invite the client to authenticate
    again, which cannot help.
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
