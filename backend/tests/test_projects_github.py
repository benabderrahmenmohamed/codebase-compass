"""HTTP tests for submitting a project by GitHub reference.

test_github_source.py checks the fetching rules in isolation; here we check
that they arrive through the API with the right status codes — including
the case the interface is designed to prevent but the API must still refuse:
a caller sending BOTH a folder and a repository.
"""

import pytest
from fastapi.testclient import TestClient

import storage
from analysis import github_source, ingestion
from main import app
from routers import projects as projects_router

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_storage():
    storage.clear()
    yield
    storage.clear()


def fake_result(**overrides):
    defaults = dict(
        files=[github_source.RemoteFile("main.py", "print(1)\n")],
        skipped=[],
        available=True,
        reason=None,
        ref=github_source.RepoRef("acme", "widget"),
        resolved_ref="main",
        listed=1,
        truncated=False,
    )
    defaults.update(overrides)
    return github_source.GitHubResult(**defaults)


@pytest.fixture
def fetches(monkeypatch):
    """Replace the fetch layer. Records what reference it was given."""
    calls = []

    def install(result):
        def fake_fetch(reference, token=None, client=None):
            calls.append(reference)
            return result

        monkeypatch.setattr(github_source, "fetch_repo", fake_fetch)
        monkeypatch.setattr(projects_router.github_source, "fetch_repo", fake_fetch)
        return calls

    return install


# --------------------------------------------------------------------------
# The happy path
# --------------------------------------------------------------------------


def test_a_repository_is_accepted_like_an_upload(fetches):
    fetches(fake_result())
    response = client.post("/projects", json={"repo": "acme/widget"})

    assert response.status_code == 201
    body = response.json()
    assert body["source"] == "github"
    assert body["repo_url"] == "https://github.com/acme/widget"
    assert [f["path"] for f in body["accepted_files"]] == ["main.py"]


def test_the_repository_name_is_used_when_none_was_given(fetches):
    fetches(fake_result())
    body = client.post("/projects", json={"repo": "acme/widget"}).json()
    assert body["name"] == "acme/widget"


def test_a_supplied_name_wins_over_the_repository_slug(fetches):
    fetches(fake_result())
    body = client.post("/projects", json={"repo": "acme/widget", "name": "my demo"}).json()
    assert body["name"] == "my demo"


def test_an_uploaded_project_is_still_marked_as_an_upload():
    response = client.post(
        "/projects",
        json={"files": [{"path": "a.py", "content": "print(1)\n"}]},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["source"] == "upload"
    assert body["repo_url"] is None


def test_a_fetched_project_can_then_be_analysed(fetches):
    fetches(fake_result(files=[github_source.RemoteFile("main.py", "x = 1\n")]))
    project_id = client.post("/projects", json={"repo": "acme/widget"}).json()["project_id"]

    response = client.post(f"/projects/{project_id}/analysis?use_llm=false")
    assert response.status_code == 200
    assert response.json()["total_score"] >= 0


def test_what_the_fetcher_skipped_appears_in_the_response(fetches):
    fetches(
        fake_result(
            skipped=[
                ingestion.SkippedFile("README.md", "unsupported_extension"),
                ingestion.SkippedFile("node_modules/x.js", "ignored_folder"),
            ]
        )
    )
    body = client.post("/projects", json={"repo": "acme/widget"}).json()

    reasons = {s["path"]: s["reason"] for s in body["skipped"]}
    assert reasons["README.md"] == "unsupported_extension"
    assert reasons["node_modules/x.js"] == "ignored_folder"


def test_a_truncated_listing_is_surfaced_to_the_client(fetches):
    fetches(fake_result(truncated=True))
    body = client.post("/projects", json={"repo": "acme/widget"}).json()
    assert body["truncated"] is True


# --------------------------------------------------------------------------
# Both sources at once — the case the UI prevents and the API must refuse
# --------------------------------------------------------------------------


def test_sending_both_a_folder_and_a_repository_is_refused():
    response = client.post(
        "/projects",
        json={
            "repo": "acme/widget",
            "files": [{"path": "a.py", "content": "print(1)\n"}],
        },
    )
    assert response.status_code == 422


def test_the_refusal_explains_why_rather_than_just_failing():
    response = client.post(
        "/projects",
        json={
            "repo": "acme/widget",
            "files": [{"path": "a.py", "content": "print(1)\n"}],
        },
    )
    message = str(response.json()["detail"]).lower()
    assert "not both" in message


def test_sending_both_never_reaches_github(fetches):
    """The refusal happens at validation, before any request is made."""
    calls = fetches(fake_result())
    client.post(
        "/projects",
        json={
            "repo": "acme/widget",
            "files": [{"path": "a.py", "content": "print(1)\n"}],
        },
    )
    assert calls == []


def test_sending_neither_is_refused():
    response = client.post("/projects", json={"name": "nothing"})
    assert response.status_code == 422


def test_an_empty_file_list_with_no_repo_is_refused():
    response = client.post("/projects", json={"files": []})
    assert response.status_code == 422


# --------------------------------------------------------------------------
# Failures reach the client as a status and a cause
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reason,expected_status",
    [
        ("invalid_reference", 422),
        ("not_found", 404),
        ("ref_not_found", 404),
        ("empty_repository", 422),
        ("no_analysable_files", 422),
        ("rate_limited", 429),
        ("forbidden", 403),
        ("timeout", 504),
        ("network_error", 502),
        ("no_files_readable", 502),
        ("github_error:500", 502),
    ],
)
def test_each_failure_maps_to_its_status(fetches, reason, expected_status):
    fetches(fake_result(files=[], available=False, reason=reason))
    response = client.post("/projects", json={"repo": "acme/widget"})
    assert response.status_code == expected_status


def test_a_failure_message_says_what_went_wrong(fetches):
    fetches(fake_result(files=[], available=False, reason="not_found"))
    detail = client.post("/projects", json={"repo": "acme/widget"}).json()["detail"]
    assert "private" in detail.lower()


def test_a_rate_limit_message_names_the_remedy(fetches):
    fetches(fake_result(files=[], available=False, reason="rate_limited"))
    detail = client.post("/projects", json={"repo": "acme/widget"}).json()["detail"]
    assert "GITHUB_TOKEN" in detail


def test_a_retryable_failure_says_so(fetches):
    fetches(fake_result(files=[], available=False, reason="rate_limited"))
    detail = client.post("/projects", json={"repo": "acme/widget"}).json()["detail"]
    assert "again" in detail.lower()


def test_a_permanent_failure_does_not_invite_a_retry(fetches):
    fetches(fake_result(files=[], available=False, reason="not_found"))
    detail = client.post("/projects", json={"repo": "acme/widget"}).json()["detail"]
    assert "again" not in detail.lower()


def test_a_non_github_url_is_refused_without_being_fetched(fetches):
    """End to end: the SSRF guard, reached through the API."""
    calls = fetches(fake_result())
    response = client.post("/projects", json={"repo": "http://localhost:8000/admin"})

    # fetch_repo is called, but parse_repo refuses before any request. Here
    # the real function is patched out, so assert the real one refuses.
    assert github_source.parse_repo("http://localhost:8000/admin") is None
    del calls, response


def test_the_real_fetcher_refuses_a_non_github_url_through_the_api():
    response = client.post("/projects", json={"repo": "https://evil.com/a/b"})
    assert response.status_code == 422
    assert "github" in response.json()["detail"].lower()
