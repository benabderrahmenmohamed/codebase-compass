"""Issuing and verifying JSON Web Tokens.

A JWT is a signed statement: "the holder of this string is `sub`, with role
`role`, until `exp`". The signature is what makes it trustworthy — anyone
can read a JWT, nobody can alter one without the secret.

This module knows nothing about HTTP and nothing about the database. It
turns a name and a role into a token, and a token back into a name and a
role, or a reason why not.

**Why HS256 rather than RS256.**
HS256 signs with one shared secret; RS256 signs with a private key that
others verify with a public one. RS256 matters when a DIFFERENT service
must verify tokens this one issued, because it can do so without holding
the signing key. Here one application issues and verifies, so the
asymmetric key pair would add key management for a property nobody uses.
That reasoning reverses the day a second service needs to verify.

**Why the algorithm is pinned on verification.**
This is the one detail in JWT that has produced real-world breaches. A
token carries its own algorithm in the header, and a naive library call
trusts it. Two attacks follow. `alg: none` claims the token is unsigned and
was accepted by several libraries for years. The RS256-to-HS256 confusion
attack is subtler: an attacker takes the PUBLIC key — which is public —
re-signs a forged token with HS256 using that public key as the shared
secret, and a verifier that trusts the header validates it happily.

The defence is to never ask the token what algorithm to use. `algorithms`
below is a fixed list, so a token arriving with any other header is
rejected before its signature is even considered.

**On revocation, stated plainly.**
A stateless token cannot be withdrawn. Deleting a user, or demoting them,
does not invalidate a token already in their hands — it stays valid until
it expires. That is the cost of not querying the database on every request,
and the mitigation is a short lifetime rather than a pretence. A denylist
of revoked identifiers would fix it and would reintroduce the per-request
lookup the design avoids; `jti` is issued below so that remains possible
without a token format change.
"""

from datetime import datetime, timedelta, timezone
from typing import NamedTuple
from uuid import uuid4

import jwt

import settings

# Pinned. Never read from the incoming token's header — see the module
# docstring for what happens when it is.
ALGORITHM = "HS256"
ALGORITHMS = [ALGORITHM]

# Short, because a stateless token cannot be revoked. Eight hours covers a
# working day without leaving a demoted account privileged for a week.
ACCESS_TOKEN_LIFETIME = timedelta(hours=8)

# Names the tokens we accept, so a token minted by some other system that
# happens to share a secret is not honoured here.
ISSUER = "codebase-compass"

# A few seconds of tolerance for clocks that disagree. Without it a token
# issued by a server whose clock is a moment ahead is rejected as
# not-yet-valid by one a moment behind.
LEEWAY_SECONDS = 10


class TokenError(Exception):
    """A domain error carrying a stable reason. The router maps it to 401."""

    def __init__(self, reason: str, message: str):
        self.reason = reason
        super().__init__(message)


class Claims(NamedTuple):
    """What a verified token asserts."""

    name: str
    role: str
    token_id: str
    issued_at: datetime
    expires_at: datetime


# RFC 7518 section 3.2: a key for HS256 must be at least as long as the
# hash output, which is 256 bits — 32 bytes. A shorter secret can be
# brute-forced offline by anyone holding one token, since they can test
# candidate keys against its signature without contacting the server.
#
# PyJWT warns about this rather than refusing. A warning in a log nobody
# reads is not a control, so it is enforced here.
MIN_SECRET_BYTES = 32


def _secret() -> str:
    secret = settings.jwt_secret()
    if not secret:
        # Refusing beats falling back to a default. A hardcoded development
        # secret is the single most copied security bug in tutorials: it
        # reaches production, and anyone who has read the source can mint an
        # administrator token.
        raise TokenError(
            "no_secret",
            "COMPASS_JWT_SECRET is not set, so tokens cannot be signed or "
            "verified. Generate one with: python -c \"import secrets; "
            "print(secrets.token_urlsafe(48))\"",
        )

    if len(secret.encode("utf-8")) < MIN_SECRET_BYTES:
        raise TokenError(
            "weak_secret",
            f"COMPASS_JWT_SECRET is shorter than {MIN_SECRET_BYTES} bytes, which "
            "RFC 7518 requires for HS256. A shorter key can be brute-forced "
            "offline from a single captured token. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(48))"',
        )

    return secret


def issue(name: str, role: str, lifetime: timedelta = ACCESS_TOKEN_LIFETIME) -> str:
    """Sign a token for this user.

    The role is inside the token so that authorising a request needs no
    database read. The consequence is stated in the module docstring: a role
    change does not reach a token already issued.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": name,                       # subject: who this is
        "role": role,
        "iss": ISSUER,                     # issuer: who signed it
        "iat": int(now.timestamp()),       # issued at
        "exp": int((now + lifetime).timestamp()),
        "jti": uuid4().hex,                # unique id, for a future denylist
    }
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM)


def verify(token: str) -> Claims:
    """Check a token and return what it asserts, or raise TokenError.

    Every failure is a distinct reason, because "invalid token" tells a
    developer nothing about whether to refresh, re-authenticate, or fix a
    configuration mistake.
    """
    if not token:
        raise TokenError("missing", "No token was supplied.")

    try:
        payload = jwt.decode(
            token,
            _secret(),
            algorithms=ALGORITHMS,   # pinned; the header is not consulted
            issuer=ISSUER,
            leeway=LEEWAY_SECONDS,
            options={
                "require": ["sub", "role", "exp", "iat", "iss"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
            },
        )
    except jwt.ExpiredSignatureError as error:
        raise TokenError("expired", "This token has expired. Sign in again.") from error
    except jwt.InvalidIssuerError as error:
        raise TokenError("wrong_issuer", "This token was not issued by this service.") from error
    except jwt.MissingRequiredClaimError as error:
        raise TokenError("incomplete", f"The token is missing a required claim: {error}.") from error
    except jwt.InvalidSignatureError as error:
        raise TokenError("bad_signature", "This token's signature does not match.") from error
    except jwt.InvalidAlgorithmError as error:
        # Reached when a token names an algorithm we do not accept — the
        # `alg: none` and RS256-to-HS256 attacks both land here.
        raise TokenError("bad_algorithm", "This token uses an unaccepted algorithm.") from error
    except jwt.DecodeError as error:
        raise TokenError("malformed", "This token could not be read.") from error
    except jwt.InvalidTokenError as error:  # anything else PyJWT defines
        raise TokenError("invalid", "This token is not valid.") from error

    name = payload.get("sub")
    role = payload.get("role")
    if not isinstance(name, str) or not name.strip():
        raise TokenError("incomplete", "The token names no subject.")
    if not isinstance(role, str) or not role.strip():
        raise TokenError("incomplete", "The token carries no role.")

    return Claims(
        name=name,
        role=role,
        token_id=payload.get("jti", ""),
        issued_at=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
        expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
    )
