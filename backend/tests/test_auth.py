"""Authentication: passwords, tokens, and the login endpoint.

Split three ways, because these are three different problems that get
confused with one another:

  * passwords.py  — is this the right password?
  * tokens.py     — is this token genuine, and what does it assert?
  * routers/auth  — turning the two into a 200 or a 401.

The token tests are mostly ATTACKS. A test that only checks a valid token
is accepted proves nothing: the interesting property is what happens to a
forged one.
"""

import base64
import json
import time
from datetime import timedelta

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

import passwords
import permissions
import storage
import tokens
from main import app

client = TestClient(app)

PASSWORD = "a-long-enough-test-passphrase"


@pytest.fixture(autouse=True)
def people():
    storage.clear()
    storage.save_user("alice", permissions.DEVELOPER, passwords.hash_password(PASSWORD))
    storage.save_user("root", permissions.ADMIN, passwords.hash_password(PASSWORD))
    # An account with no password: it exists and cannot log in.
    storage.save_user("mute", permissions.DEVELOPER, None)
    yield
    storage.clear()


def login(name, password):
    return client.post("/auth/login", json={"name": name, "password": password})


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ==========================================================================
# Passwords
# ==========================================================================


def test_a_password_verifies_against_its_own_hash():
    digest = passwords.hash_password(PASSWORD)
    assert passwords.verify(digest, PASSWORD) is True


def test_a_wrong_password_does_not():
    digest = passwords.hash_password(PASSWORD)
    assert passwords.verify(digest, PASSWORD + "x") is False


def test_the_same_password_hashes_differently_every_time():
    """A per-password random salt is what stops one rainbow table breaking
    every account at once, and what stops two users with the same password
    being visibly identical in the database."""
    assert passwords.hash_password(PASSWORD) != passwords.hash_password(PASSWORD)


def test_the_hash_is_argon2id_not_something_older():
    assert passwords.hash_password(PASSWORD).startswith("$argon2id$")


def test_the_stated_cost_parameters_are_the_ones_used():
    """They are written down in the module rather than inherited silently,
    so a reader can see the question was asked."""
    digest = passwords.hash_password(PASSWORD)
    assert f"m={passwords.MEMORY_COST_KIB}" in digest
    assert f"t={passwords.TIME_COST}" in digest
    assert f"p={passwords.PARALLELISM}" in digest


def test_a_short_password_is_refused():
    with pytest.raises(passwords.PasswordTooShort):
        passwords.hash_password("short")


def test_an_absurdly_long_password_is_refused():
    """Unbounded input is unbounded work: a megabyte password would be a
    cheap way to burn server CPU."""
    with pytest.raises(passwords.PasswordTooLong):
        passwords.hash_password("x" * (passwords.MAX_PASSWORD_LENGTH + 1))


def test_verifying_against_no_stored_hash_is_false_not_an_error():
    assert passwords.verify(None, PASSWORD) is False


def test_a_corrupted_hash_fails_closed():
    assert passwords.verify("not-a-real-argon2-hash", PASSWORD) is False


def test_a_hash_made_with_current_settings_does_not_need_rehashing():
    assert passwords.needs_rehash(passwords.hash_password(PASSWORD)) is False


# ==========================================================================
# Tokens — mostly attacks
# ==========================================================================


def test_a_token_round_trips():
    claims = tokens.verify(tokens.issue("alice", "developer"))
    assert (claims.name, claims.role) == ("alice", "developer")


def test_a_token_carries_an_expiry_and_a_unique_id():
    claims = tokens.verify(tokens.issue("alice", "developer"))
    assert claims.expires_at > claims.issued_at
    assert claims.token_id


def test_two_tokens_have_different_identifiers():
    """jti exists so a denylist remains possible without changing the token
    format — see the note on revocation in tokens.py."""
    first = tokens.verify(tokens.issue("alice", "developer")).token_id
    second = tokens.verify(tokens.issue("alice", "developer")).token_id
    assert first != second


# --- the attack that pinning the algorithm prevents ----------------------


def test_an_unsigned_token_is_rejected():
    """`alg: none` claims the token needs no signature. Libraries that read
    the algorithm from the token accepted these for years."""
    forged = pyjwt.encode(
        {
            "sub": "alice",
            "role": "admin",
            "iss": tokens.ISSUER,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        key="",
        algorithm="none",
    )
    with pytest.raises(tokens.TokenError) as raised:
        tokens.verify(forged)
    assert raised.value.reason == "bad_algorithm"


def test_a_token_signed_with_another_secret_is_rejected():
    forged = pyjwt.encode(
        {
            "sub": "alice",
            "role": "admin",
            "iss": tokens.ISSUER,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        key="a-completely-different-secret-that-is-long-enough",
        algorithm="HS256",
    )
    with pytest.raises(tokens.TokenError) as raised:
        tokens.verify(forged)
    assert raised.value.reason == "bad_signature"


def test_editing_the_role_inside_a_token_invalidates_it():
    """The whole point of the signature: privilege escalation by editing
    the payload must not work."""
    header, body, signature = tokens.issue("alice", "developer").split(".")
    payload = json.loads(base64.urlsafe_b64decode(body + "=="))
    payload["role"] = "admin"
    tampered = (
        header
        + "."
        + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        + "."
        + signature
    )

    with pytest.raises(tokens.TokenError) as raised:
        tokens.verify(tampered)
    assert raised.value.reason == "bad_signature"


def test_an_expired_token_is_rejected_and_says_so():
    expired = tokens.issue("alice", "developer", lifetime=timedelta(seconds=-3600))
    with pytest.raises(tokens.TokenError) as raised:
        tokens.verify(expired)
    assert raised.value.reason == "expired"


def test_a_token_from_another_issuer_is_rejected():
    """Two systems sharing a secret must not accept each other's tokens."""
    foreign = pyjwt.encode(
        {
            "sub": "alice",
            "role": "admin",
            "iss": "some-other-service",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        key=tokens._secret(),
        algorithm="HS256",
    )
    with pytest.raises(tokens.TokenError) as raised:
        tokens.verify(foreign)
    assert raised.value.reason == "wrong_issuer"


def test_a_token_missing_a_required_claim_is_rejected():
    incomplete = pyjwt.encode(
        {"sub": "alice", "iss": tokens.ISSUER, "iat": int(time.time()),
         "exp": int(time.time()) + 3600},
        key=tokens._secret(),
        algorithm="HS256",
    )
    with pytest.raises(tokens.TokenError) as raised:
        tokens.verify(incomplete)
    assert raised.value.reason == "incomplete"


def test_rubbish_is_rejected_without_crashing():
    for rubbish in ("", "not.a.token", "a", "...", "x" * 500):
        with pytest.raises(tokens.TokenError):
            tokens.verify(rubbish)


def test_a_secret_shorter_than_the_rfc_minimum_is_refused(monkeypatch):
    """RFC 7518 requires a key at least as long as the hash output for
    HS256. PyJWT only warns; a warning in a log nobody reads is not a
    control."""
    monkeypatch.setenv("COMPASS_JWT_SECRET", "too-short")
    with pytest.raises(tokens.TokenError) as raised:
        tokens.issue("alice", "developer")
    assert raised.value.reason == "weak_secret"


def test_no_secret_means_no_tokens_rather_than_a_default(monkeypatch):
    """A hardcoded development secret is the most-copied security bug in
    tutorials: it reaches production and anyone who read the source can
    mint an admin token."""
    monkeypatch.delenv("COMPASS_JWT_SECRET", raising=False)
    with pytest.raises(tokens.TokenError) as raised:
        tokens.issue("alice", "developer")
    assert raised.value.reason == "no_secret"


# ==========================================================================
# The login endpoint
# ==========================================================================


def test_correct_credentials_return_a_usable_token():
    response = login("alice", PASSWORD)

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["role"] == "developer"
    assert tokens.verify(body["access_token"]).name == "alice"


def test_the_response_says_what_the_role_may_do():
    """So a client can render the interface it is allowed to use without
    decoding the token itself — decoding client-side invites treating
    unverified claims as authoritative."""
    body = login("alice", PASSWORD).json()
    assert permissions.SUBMIT_PROJECT in body["permissions"]
    assert permissions.MANAGE_USERS not in body["permissions"]


def test_the_response_says_when_the_token_expires():
    assert login("alice", PASSWORD).json()["expires_in"] == int(
        tokens.ACCESS_TOKEN_LIFETIME.total_seconds()
    )


def test_a_wrong_password_is_401():
    assert login("alice", "wrong-password-entirely").status_code == 401


def test_an_unknown_user_is_401():
    assert login("nobody", PASSWORD).status_code == 401


# Saying "no such user" versus "wrong password" hands an attacker a way to
# confirm which accounts exist, turning one guess into two easier problems.
def test_both_failures_give_the_identical_message():
    wrong = login("alice", "wrong-password-entirely")
    missing = login("nobody", PASSWORD)

    assert wrong.json() == missing.json()
    assert wrong.status_code == missing.status_code


def test_a_failed_login_says_how_to_authenticate():
    """RFC 6750: a 401 on a bearer-token API carries WWW-Authenticate."""
    assert "Bearer" in login("alice", "wrong").headers.get("www-authenticate", "")


def test_an_account_without_a_password_cannot_log_in():
    assert login("mute", PASSWORD).status_code == 401
    assert login("mute", "").status_code == 422  # empty password fails validation


def test_the_password_hash_never_appears_in_any_response():
    """response_model filters it out — the same mechanism that keeps
    submitted file contents out of a project response."""
    token = login("root", PASSWORD).json()["access_token"]

    bodies = [
        login("alice", PASSWORD).text,
        client.get("/users", headers=bearer(token)).text,
        client.get("/users/me", headers=bearer(token)).text,
    ]
    for body in bodies:
        assert "password_hash" not in body
        assert "$argon2id$" not in body


# ==========================================================================
# The token in use, through the API
# ==========================================================================


def test_a_bearer_token_authenticates_a_request():
    token = login("alice", PASSWORD).json()["access_token"]
    body = client.get("/users/me", headers=bearer(token)).json()

    assert body["name"] == "alice"
    assert body["role"] == "developer"


def test_no_token_is_a_guest_rather_than_an_error():
    """The tool is deliberately usable without an account: the
    deterministic report costs nothing and needs nobody's permission."""
    body = client.get("/users/me").json()
    assert body["role"] == permissions.GUEST


def test_a_malformed_authorization_header_is_401():
    for header in ({"Authorization": "alice"},
                   {"Authorization": "Basic YWxpY2U6cGFzcw=="},
                   {"Authorization": "Bearer"},
                   {"Authorization": "Bearer "}):
        assert client.get("/users/me", headers=header).status_code == 401


def test_an_expired_token_is_401_not_403():
    """401 means "I do not know who you are" and sends a client to the
    login page. 403 would send them to a support desk."""
    expired = tokens.issue("alice", "developer", lifetime=timedelta(hours=-1))
    response = client.get("/users/me", headers=bearer(expired))

    assert response.status_code == 401
    assert "expired" in response.headers.get("www-authenticate", "")


def test_the_clock_skew_leeway_extends_expiry_by_exactly_that_much():
    """Written down because it surprised me while writing these tests.

    The leeway exists so two servers whose clocks disagree by a second do
    not reject each other's tokens. PyJWT applies it to `exp` as well as to
    `iat`, so a token is honoured for LEEWAY_SECONDS past its stated
    expiry. On an eight-hour token that is 0.03% of its life and worth the
    robustness — but it is a real extension, not zero, and a reader should
    not have to discover it by writing a failing test.
    """
    just_expired = tokens.issue(
        "alice", "developer", lifetime=timedelta(seconds=-(tokens.LEEWAY_SECONDS // 2))
    )
    assert tokens.verify(just_expired).name == "alice"

    well_expired = tokens.issue(
        "alice", "developer", lifetime=timedelta(seconds=-(tokens.LEEWAY_SECONDS + 5))
    )
    with pytest.raises(tokens.TokenError) as raised:
        tokens.verify(well_expired)
    assert raised.value.reason == "expired"


def test_a_deleted_account_stops_working_immediately():
    """A role change does not reach a token already issued — that is the
    cost of a stateless token. Deletion is different: it is what happens
    when someone leaves or is compromised, so it is checked per request."""
    token = login("alice", PASSWORD).json()["access_token"]
    assert client.get("/users/me", headers=bearer(token)).status_code == 200

    storage.delete_user("alice")

    assert client.get("/users/me", headers=bearer(token)).status_code == 401


# The header that used to be the whole authentication mechanism.
def test_the_old_x_user_header_no_longer_authenticates_anything():
    """Leaving it as a development fallback is how such holes reach
    production. Sending X-User: root must not make anybody an admin."""
    response = client.get("/users/me", headers={"X-User": "root"})

    assert response.status_code == 200          # a guest, not an error
    assert response.json()["role"] == permissions.GUEST
    assert response.json()["name"] != "root"


def test_x_user_cannot_reach_an_admin_only_endpoint():
    assert client.get("/users", headers={"X-User": "root"}).status_code == 403


def test_a_token_is_required_for_the_paid_layer():
    """A guest still cannot spend the owner's API credit."""
    created = client.post("/projects", json={"files": [{"path": "a.py", "content": "x = 1\n"}]}).json()
    report = client.post(f"/projects/{created['project_id']}/analysis?use_llm=true").json()

    assert report["llm_used"] is False


def test_an_admin_can_create_a_user_with_a_password_and_they_can_log_in():
    token = login("root", PASSWORD).json()["access_token"]

    created = client.post(
        "/users",
        json={"name": "dave", "role": "lead", "password": "another-long-passphrase"},
        headers=bearer(token),
    )
    assert created.status_code == 201

    signed_in = login("dave", "another-long-passphrase")
    assert signed_in.status_code == 200
    assert signed_in.json()["role"] == "lead"


def test_a_short_password_is_refused_at_the_api_too():
    token = login("root", PASSWORD).json()["access_token"]

    response = client.post(
        "/users",
        json={"name": "dave", "role": "developer", "password": "short"},
        headers=bearer(token),
    )

    assert response.status_code == 422
    assert "at least" in response.json()["detail"]


def test_changing_a_role_does_not_erase_the_password():
    """INSERT OR REPLACE would wipe it, leaving an account that silently
    cannot log in with nothing in the logs to say why."""
    token = login("root", PASSWORD).json()["access_token"]

    client.post(
        "/users", json={"name": "alice", "role": "lead"}, headers=bearer(token)
    )

    assert login("alice", PASSWORD).status_code == 200
    assert login("alice", PASSWORD).json()["role"] == "lead"
