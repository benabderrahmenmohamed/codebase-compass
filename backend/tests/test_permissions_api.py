"""Permissions enforced through the API.

A matrix nobody checks is a document. These tests drive the real endpoints
and assert that the rules actually bite.
"""

import pytest
from fastapi.testclient import TestClient

import passwords
import permissions
import storage
import tokens
from main import app

client = TestClient(app)

SNIPPET = {"code": "x = 1\n", "language": "python"}
PROJECT = {"files": [{"path": "a.py", "content": "x = 1\n"}]}


PASSWORD = "a-long-enough-test-passphrase"


@pytest.fixture(autouse=True)
def people():
    storage.clear()
    digest = passwords.hash_password(PASSWORD)
    storage.save_user("alice", permissions.DEVELOPER, digest)
    storage.save_user("bob", permissions.DEVELOPER, digest)
    storage.save_user("carol", permissions.LEAD, digest)
    storage.save_user("root", permissions.ADMIN, digest)
    yield
    storage.clear()


def as_user(name):
    """A real bearer token for this user.

    The X-User header this used to send no longer authenticates anything:
    claiming a name is not proving one. Tokens are minted directly rather
    than by calling /auth/login, because Argon2 is deliberately slow and
    these tests are about authorisation, not about the login flow —
    test_auth.py exercises that.
    """
    if not name:
        return {}
    record = storage.get_user(name)
    if record is None:
        # An unknown name: issue a token for it anyway, so the "unknown
        # user" path can still be tested.
        return {"Authorization": f"Bearer {tokens.issue(name, permissions.DEVELOPER)}"}
    return {"Authorization": f"Bearer {tokens.issue(record['name'], record['role'])}"}


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------


def test_no_header_is_a_guest():
    body = client.get("/users/me").json()
    assert body["role"] == permissions.GUEST
    # Not the shared "anonymous" any more: each browser gets its own guest
    # identity, or every visitor sees every other visitor's submissions.
    assert body["name"].startswith(permissions.GUEST_PREFIX)


def test_a_known_name_gets_its_role():
    body = client.get("/users/me", headers=as_user("carol")).json()
    assert (body["name"], body["role"]) == ("carol", permissions.LEAD)


def test_a_token_for_a_deleted_account_is_rejected():
    """This used to assert that an unknown name fell back to guest, which
    was right when a name was merely claimed. A SIGNED token naming an
    account that no longer exists is different: deleting a user is the
    action taken when someone leaves or is compromised, and it has to take
    effect immediately rather than when their token happens to expire."""
    response = client.get("/users/me", headers=as_user("nobody"))

    assert response.status_code == 401
    assert "revoked" in response.headers.get("www-authenticate", "")


def test_whoami_lists_what_the_role_may_do():
    """A client needs this to render only the actions it is allowed."""
    body = client.get("/users/me", headers=as_user("root")).json()
    assert permissions.MANAGE_USERS in body["permissions"]
    assert permissions.USE_LLM in body["permissions"]


def test_whoami_is_open_to_guests():
    assert client.get("/users/me").status_code == 200


# --------------------------------------------------------------------------
# The paid layer, which is the cost control
# --------------------------------------------------------------------------


def test_a_guest_analysis_runs_without_the_paid_layer():
    project_id = client.post("/projects", json=PROJECT).json()["project_id"]

    report = client.post(f"/projects/{project_id}/analysis").json()

    assert report["llm_used"] is False
    # Degraded, not refused: the deterministic report is complete.
    assert report["total_score"] >= 0
    assert report["files"]


def test_a_guest_asking_for_the_paid_layer_is_not_an_error():
    """Refusing would punish curiosity; charging silently would be worse."""
    project_id = client.post("/projects", json=PROJECT).json()["project_id"]

    response = client.post(f"/projects/{project_id}/analysis?use_llm=true")

    assert response.status_code == 200
    assert response.json()["llm_used"] is False


def test_a_developer_may_request_the_paid_layer():
    """No key is configured in tests, so it degrades to no_api_key rather
    than 'disabled' — which is what proves the permission let it through."""
    created = client.post("/projects", json=PROJECT, headers=as_user("alice")).json()

    report = client.post(
        f"/projects/{created['project_id']}/analysis", headers=as_user("alice")
    ).json()

    assert report["llm_reason"] == "no_api_key"


# --------------------------------------------------------------------------
# Ownership
# --------------------------------------------------------------------------


def test_a_submission_records_its_owner():
    body = client.post("/projects", json=PROJECT, headers=as_user("alice")).json()
    assert body["owner"] == "alice"


def test_a_guest_submission_is_owned_by_that_guest():
    body = client.post("/projects", json=PROJECT).json()
    assert body["owner"].startswith(permissions.GUEST_PREFIX)


def test_a_developer_does_not_see_another_developers_projects():
    client.post("/projects", json=PROJECT, headers=as_user("alice"))
    client.post("/projects", json=PROJECT, headers=as_user("bob"))

    mine = client.get("/projects", headers=as_user("alice")).json()

    assert [p["owner"] for p in mine] == ["alice"]


def test_a_lead_sees_everybodys_projects():
    client.post("/projects", json=PROJECT, headers=as_user("alice"))
    client.post("/projects", json=PROJECT, headers=as_user("bob"))

    everything = client.get("/projects", headers=as_user("carol")).json()

    assert sorted(p["owner"] for p in everything) == ["alice", "bob"]


def test_the_same_isolation_applies_to_analyses():
    client.post("/analyses", json=SNIPPET, headers=as_user("alice"))
    client.post("/analyses", json=SNIPPET, headers=as_user("bob"))

    assert len(client.get("/analyses", headers=as_user("alice")).json()) == 1
    assert len(client.get("/analyses", headers=as_user("carol")).json()) == 2


# Answering 403 would confirm the id exists and belongs to somebody else,
# which turns the endpoint into an oracle for enumerating other people's work.
def test_reading_someone_elses_project_answers_404_not_403():
    created = client.post("/projects", json=PROJECT, headers=as_user("alice")).json()

    response = client.get(f"/projects/{created['project_id']}", headers=as_user("bob"))

    assert response.status_code == 404
    assert response.json()["detail"] == "Project not found"


def test_the_same_answer_as_an_id_that_never_existed():
    created = client.post("/projects", json=PROJECT, headers=as_user("alice")).json()

    denied = client.get(f"/projects/{created['project_id']}", headers=as_user("bob"))
    missing = client.get("/projects/never-issued", headers=as_user("bob"))

    assert denied.status_code == missing.status_code
    assert denied.json() == missing.json()


def test_a_developer_cannot_analyse_someone_elses_project():
    created = client.post("/projects", json=PROJECT, headers=as_user("alice")).json()

    response = client.post(
        f"/projects/{created['project_id']}/analysis", headers=as_user("bob")
    )

    assert response.status_code == 404


def test_a_lead_can_read_another_users_project():
    created = client.post("/projects", json=PROJECT, headers=as_user("alice")).json()

    response = client.get(f"/projects/{created['project_id']}", headers=as_user("carol"))

    assert response.status_code == 200


# --------------------------------------------------------------------------
# User management
# --------------------------------------------------------------------------


def test_only_an_admin_may_list_users():
    assert client.get("/users", headers=as_user("carol")).status_code == 403
    assert client.get("/users", headers=as_user("root")).status_code == 200


def test_a_guest_may_not_manage_users():
    assert client.post("/users", json={"name": "x", "role": "admin"}).status_code == 403


def test_an_admin_creates_a_user():
    response = client.post(
        "/users", json={"name": "dave", "role": "developer"}, headers=as_user("root")
    )

    assert response.status_code == 201
    assert storage.get_user("dave")["role"] == "developer"


def test_a_new_user_immediately_has_their_role():
    client.post(
        "/users", json={"name": "dave", "role": "lead"}, headers=as_user("root")
    )
    assert client.get("/users/me", headers=as_user("dave")).json()["role"] == "lead"


def test_an_unknown_role_is_refused_rather_than_stored():
    """A role outside the matrix holds no permissions, so the user would
    exist and be able to do nothing — confusing to debug."""
    response = client.post(
        "/users", json={"name": "dave", "role": "wizard"}, headers=as_user("root")
    )

    assert response.status_code == 422
    assert "wizard" in response.json()["detail"]
    assert storage.get_user("dave") is None


def test_an_admin_removes_a_user():
    assert client.delete("/users/alice", headers=as_user("root")).status_code == 204
    assert storage.get_user("alice") is None


def test_removing_an_unknown_user_is_404():
    assert client.delete("/users/ghost", headers=as_user("root")).status_code == 404


def test_an_admin_cannot_remove_themselves():
    """Otherwise a system can end up with no admin and no way back in."""
    assert client.delete("/users/root", headers=as_user("root")).status_code == 422
    assert storage.get_user("root") is not None


# --------------------------------------------------------------------------
# Bootstrapping the first admin
# --------------------------------------------------------------------------


BOOTSTRAP = "a-long-enough-bootstrap-secret"


def test_the_bootstrap_secret_can_create_the_first_admin(monkeypatch):
    storage.clear()
    monkeypatch.setenv("COMPASS_BOOTSTRAP_TOKEN", BOOTSTRAP)

    response = client.post(
        "/users",
        json={"name": "root", "role": "admin"},
        headers={"X-Bootstrap-Token": BOOTSTRAP},
    )

    assert response.status_code == 201


def test_a_wrong_bootstrap_secret_is_refused(monkeypatch):
    storage.clear()
    monkeypatch.setenv("COMPASS_BOOTSTRAP_TOKEN", BOOTSTRAP)

    response = client.post(
        "/users",
        json={"name": "root", "role": "admin"},
        headers={"X-Bootstrap-Token": "not-the-secret-at-all"},
    )

    assert response.status_code == 403


def test_a_short_bootstrap_secret_is_treated_as_none(monkeypatch):
    """Failing closed beats accepting a four-character token somebody set
    'just for testing'."""
    storage.clear()
    monkeypatch.setenv("COMPASS_BOOTSTRAP_TOKEN", "short")

    response = client.post(
        "/users",
        json={"name": "root", "role": "admin"},
        headers={"X-Bootstrap-Token": "short"},
    )

    assert response.status_code == 403


def test_the_bootstrap_stops_working_once_a_user_exists(monkeypatch):
    """Self-closing, so it cannot be left switched on by accident."""
    monkeypatch.setenv("COMPASS_BOOTSTRAP_TOKEN", BOOTSTRAP)

    # The `people` fixture already created users.
    response = client.post(
        "/users",
        json={"name": "x", "role": "admin"},
        headers={"X-Bootstrap-Token": BOOTSTRAP},
    )

    assert response.status_code == 403


def test_without_the_variable_there_is_no_bootstrap(monkeypatch):
    storage.clear()
    monkeypatch.delenv("COMPASS_BOOTSTRAP_TOKEN", raising=False)

    response = client.post(
        "/users",
        json={"name": "root", "role": "admin"},
        headers={"X-Bootstrap-Token": BOOTSTRAP},
    )

    assert response.status_code == 403


# --------------------------------------------------------------------------
# One guest is not every guest
#
# Every anonymous visitor used to be the literal owner "anonymous", so one
# could list, read and re-analyse another's projects. The source never
# leaked — response_model strips file contents — but paths, project names
# and findings did, which is a map of somebody's weak points.
# --------------------------------------------------------------------------


def fresh_visitor():
    """A separate TestClient is a separate cookie jar: a different browser."""
    return TestClient(app)


def test_the_server_issues_a_guest_cookie():
    visitor = fresh_visitor()
    response = visitor.get("/users/me")

    from routers.security import GUEST_COOKIE

    assert GUEST_COOKIE in response.cookies


def test_the_guest_cookie_is_not_readable_by_page_scripts():
    """HttpOnly: a cross-site script cannot steal another visitor's identity."""
    visitor = fresh_visitor()
    response = visitor.get("/users/me")
    header = response.headers["set-cookie"].lower()

    assert "httponly" in header
    assert "samesite=lax" in header


def test_the_same_visitor_keeps_one_identity_across_requests():
    visitor = fresh_visitor()
    first = visitor.get("/users/me").json()["name"]
    second = visitor.get("/users/me").json()["name"]

    assert first == second


def test_two_visitors_get_different_identities():
    assert fresh_visitor().get("/users/me").json()["name"] != (
        fresh_visitor().get("/users/me").json()["name"]
    )


def test_one_guest_cannot_list_anothers_projects():
    alice_the_stranger = fresh_visitor()
    alice_the_stranger.post("/projects", json=PROJECT)

    assert fresh_visitor().get("/projects").json() == []


def test_one_guest_cannot_read_anothers_project():
    owner = fresh_visitor()
    created = owner.post("/projects", json=PROJECT).json()

    response = fresh_visitor().get(f"/projects/{created['project_id']}")

    assert response.status_code == 404


def test_one_guest_cannot_re_analyse_anothers_project():
    """Re-analysis is the expensive one: it could spend somebody's budget."""
    owner = fresh_visitor()
    created = owner.post("/projects", json=PROJECT).json()

    response = fresh_visitor().post(f"/projects/{created['project_id']}/analysis")

    assert response.status_code == 404


def test_one_guest_cannot_see_anothers_notifications():
    owner = fresh_visitor()
    created = owner.post("/projects", json=PROJECT).json()
    owner.post(f"/projects/{created['project_id']}/analysis?use_llm=false")

    assert fresh_visitor().get("/notifications").json() == []
    assert owner.get("/notifications").json() != []


def test_a_forged_cookie_gets_a_fresh_identity_rather_than_being_trusted():
    """The token must be 32 hex characters. Anything else is replaced, so a
    client cannot put arbitrary text into an owner string."""
    from routers.security import GUEST_COOKIE

    visitor = fresh_visitor()
    visitor.cookies.set(GUEST_COOKIE, "../../etc/passwd")
    name = visitor.get("/users/me").json()["name"]

    assert name.startswith(permissions.GUEST_PREFIX)
    assert "passwd" not in name


def test_a_user_cannot_be_named_to_impersonate_a_guest():
    """Guest identities share a namespace with user names."""
    response = client.post(
        "/users",
        json={"name": "guest:deadbeefdeadbeefdeadbeefdeadbeef", "role": "developer"},
        headers=as_user("root"),
    )
    assert response.status_code == 422


def test_a_user_cannot_be_named_anonymous():
    response = client.post(
        "/users", json={"name": "anonymous", "role": "developer"}, headers=as_user("root")
    )
    assert response.status_code == 422


def test_a_registered_name_still_wins_over_the_cookie():
    visitor = fresh_visitor()
    visitor.get("/users/me")  # picks up a guest cookie
    assert visitor.get("/users/me", headers=as_user("alice")).json()["name"] == "alice"
