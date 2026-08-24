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

from fastapi import Depends, Header, HTTPException, status

import permissions
import storage
from permissions import User


def identify(x_user: str | None = Header(default=None)) -> User:
    """Resolve the caller into a User.

    No header, or a name nobody registered, means the anonymous guest. An
    unknown name is deliberately NOT an error: this build has no
    registration, so refusing unknown names would make the API unusable
    before any user exists, and would leak which names are registered.
    """
    if not x_user:
        return permissions.ANONYMOUS_USER

    record = storage.get_user(x_user.strip())
    if record is None:
        return permissions.ANONYMOUS_USER
    return User(record["name"], record["role"])


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
