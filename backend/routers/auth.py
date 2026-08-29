"""Authentication: proving who you are.

Distinct from `permissions.py`, which decides what a proven identity may do.
Authentication answers "who is this?"; authorisation answers "may they?".
Conflating them is how systems end up with a role check that a forged
header satisfies.

**What is deliberately NOT here.**

*Open registration.* Anybody could create an account, and the first thing
they would do is ask for the admin role. Accounts are created by an
administrator through /users, which already requires MANAGE_USERS.

*A refresh-token flow.* Refresh tokens exist to allow short access tokens
without asking people to sign in every few minutes, and they introduce
their own storage, rotation and reuse-detection problems. An eight-hour
access token covers a working day, which is the actual requirement here.
Adding a refresh flow badly is worse than not having one.

*Logout that revokes.* A stateless token cannot be withdrawn — see
tokens.py. `POST /auth/logout` is deliberately absent rather than present
and lying; the client discards the token, and the honest statement is in
the documentation.
"""

from fastapi import APIRouter, HTTPException, status

import passwords
import permissions
import storage
import tokens
from schemas import ErrorResponse, LoginRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])

# One message for every failure. Saying "no such user" versus "wrong
# password" hands an attacker a way to confirm which accounts exist, which
# turns one guess into two separate, easier problems.
CREDENTIALS_REJECTED = "Those credentials were not accepted."


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Exchange a name and password for a token",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "The credentials were not accepted",
        },
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "model": ErrorResponse,
            "description": "No signing secret is configured, so no token can be issued",
        },
    },
)
def login(payload: LoginRequest):
    """Verify a password and issue an access token.

    The work is deliberately the same whether or not the account exists:
    `passwords.verify` hashes against a throwaway digest when there is no
    stored hash, so the response time does not answer "is this a real
    username?".
    """
    record = storage.get_user(payload.name.strip())
    stored_hash = record.get("password_hash") if record else None

    if not passwords.verify(stored_hash, payload.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=CREDENTIALS_REJECTED,
            # RFC 6750: a 401 on a bearer-token API says how to authenticate.
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Cost parameters rise as hardware gets faster. This is the only moment
    # the plaintext is in hand, so it is the only moment a stored hash can
    # be upgraded without asking anybody to change their password.
    if passwords.needs_rehash(stored_hash):
        storage.save_user(
            record["name"], record["role"], passwords.hash_password(payload.password)
        )

    try:
        token = tokens.issue(record["name"], record["role"])
    except tokens.TokenError as error:
        # A misconfigured server, not a rejected user. 503 rather than 401,
        # because retrying with better credentials cannot help.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(error)
        ) from error

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": int(tokens.ACCESS_TOKEN_LIFETIME.total_seconds()),
        "name": record["name"],
        "role": record["role"],
        "permissions": sorted(permissions.ROLE_PERMISSIONS.get(record["role"], [])),
    }
