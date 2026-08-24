"""Permissions enforced through the API.

A matrix nobody checks is a document. These tests drive the real endpoints
and assert that the rules actually bite.
"""

import pytest
from fastapi.testclient import TestClient

import permissions
import storage
from main import app

client = TestClient(app)

SNIPPET = {"code": "x = 1\n", "language": "python"}
PROJECT = {"files": [{"path": "a.py", "content": "x = 1\n"}]}


@pytest.fixture(autouse=True)
def people():
    storage.clear()
    storage.save_user("alice", permissions.DEVELOPER)
    storage.save_user("bob", permissions.DEVELOPER)
    storage.save_user("carol", permissions.LEAD)
    storage.save_user("root", permissions.ADMIN)
    yield
    storage.clear()


def as_user(name):
    return {"X-User": name} if name else {}


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------


def test_no_header_is_a_guest():
    body = client.get("/users/me").json()
    assert body["role"] == permissions.GUEST
    assert body["name"] == permissions.ANONYMOUS


def test_a_known_name_gets_its_role():
    body = client.get("/users/me", headers=as_user("carol")).json()
    assert (body["name"], body["role"]) == ("carol", permissions.LEAD)


def test_an_unknown_name_falls_back_to_guest_rather_than_erroring():
    """There is no registration in this build, so refusing unknown names
    would make the API unusable before any user exists."""
    body = client.get("/users/me", headers=as_user("nobody")).json()
    assert body["role"] == permissions.GUEST


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


def test_a_guest_submission_is_owned_by_the_anonymous_pool():
    body = client.post("/projects", json=PROJECT).json()
    assert body["owner"] == permissions.ANONYMOUS


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


def test_the_bootstrap_name_can_create_the_first_admin(monkeypatch):
    storage.clear()
    monkeypatch.setenv("COMPASS_BOOTSTRAP_ADMIN", "founder")

    response = client.post(
        "/users", json={"name": "root", "role": "admin"}, headers=as_user("founder")
    )

    assert response.status_code == 201


def test_the_bootstrap_stops_working_once_a_user_exists(monkeypatch):
    """Self-closing, so it cannot be left switched on by accident."""
    monkeypatch.setenv("COMPASS_BOOTSTRAP_ADMIN", "founder")

    # The `people` fixture already created users.
    response = client.post(
        "/users", json={"name": "x", "role": "admin"}, headers=as_user("founder")
    )

    assert response.status_code == 403


def test_without_the_variable_there_is_no_bootstrap(monkeypatch):
    storage.clear()
    monkeypatch.delenv("COMPASS_BOOTSTRAP_ADMIN", raising=False)

    response = client.post(
        "/users", json={"name": "root", "role": "admin"}, headers=as_user("founder")
    )

    assert response.status_code == 403
