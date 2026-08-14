"""HTTP tests of the /projects endpoint.

test_ingestion.py checks the filtering rules in isolation; here we check that
they are correctly applied through the API, with the right status codes and
the right response shape.
"""

import json

import pytest
from fastapi.testclient import TestClient

import storage
from analysis import ingestion
from main import app

client = TestClient(app)


SIMPLE_PROJECT = {
    "name": "demo",
    "files": [
        {"path": "app/main.py", "content": "from fastapi import FastAPI\n"},
        {"path": "app/models.py", "content": "class Order:\n    pass\n"},
        {"path": "front/index.js", "content": "console.log(1)\n"},
    ],
}


@pytest.fixture(autouse=True)
def empty_storage():
    storage.clear()


# ---------------------------------------------------------------- creation


def test_creation_returns_201_and_the_expected_shape():
    response = client.post("/projects", json=SIMPLE_PROJECT)

    assert response.status_code == 201

    body = response.json()
    assert set(body) == {
        "project_id",
        "name",
        "accepted_files",
        "skipped",
        "total_chars",
        "created_at",
    }
    assert len(body["accepted_files"]) == 3
    assert body["skipped"] == []
    assert body["name"] == "demo"


def test_each_accepted_file_carries_path_hash_and_size():
    body = client.post("/projects", json=SIMPLE_PROJECT).json()

    for file in body["accepted_files"]:
        assert set(file) == {"path", "hash", "chars"}
        assert len(file["hash"]) == 64
        assert file["chars"] > 0


def test_file_contents_never_appear_in_the_response():
    """response_model filters: submitted code is not echoed back."""
    body = client.post("/projects", json=SIMPLE_PROJECT).json()

    assert "FastAPI" not in json.dumps(body)


# ---------------------------------------------------------------- filtering


def test_a_real_project_drops_the_noise_without_failing():
    response = client.post(
        "/projects",
        json={
            "files": [
                {"path": "app/main.py", "content": "x = 1"},
                {"path": "README.md", "content": "# doc"},
                {"path": "node_modules/react/index.js", "content": "x"},
                {"path": "../secret.py", "content": "PASSWORD"},
            ]
        },
    )

    assert response.status_code == 201
    body = response.json()

    assert [f["path"] for f in body["accepted_files"]] == ["app/main.py"]
    reasons = {f["reason"] for f in body["skipped"]}
    assert reasons == {
        "unsupported_extension",
        "ignored_folder",
        "suspicious_path",
    }


@pytest.mark.parametrize(
    "path", ["../secret.py", "/etc/passwd.py", "a/../../b.py", "C:/Windows/x.py"]
)
def test_traversal_attempts_are_skipped(path):
    body = client.post(
        "/projects", json={"files": [{"path": path, "content": "x = 1"}]}
    ).json()

    assert body["accepted_files"] == []
    assert body["skipped"][0]["reason"] == "suspicious_path"


def test_a_null_byte_in_the_path_is_refused_by_the_model():
    """Here Pydantic refuses it before ingestion even runs: 422."""
    response = client.post(
        "/projects",
        json={"files": [{"path": "app/x.py\u0000.exe", "content": "x"}]},
    )

    assert response.status_code == 422


# ---------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "body",
    [
        {},  # files field missing
        {"files": []},  # no file at all
        {"files": [{"path": "", "content": "x"}]},  # empty path
        {"files": [{"path": "a.py"}]},  # content missing
    ],
)
def test_an_invalid_submission_returns_422(body):
    assert client.post("/projects", json=body).status_code == 422


# ------------------------------------------------------------------- limits


def test_file_too_large_returns_413_naming_the_file():
    huge = "x" * (ingestion.MAX_CHARS_PER_FILE + 1)

    response = client.post(
        "/projects", json={"files": [{"path": "app/huge.py", "content": huge}]}
    )

    assert response.status_code == 413
    assert "app/huge.py" in response.json()["detail"]


def test_too_many_files_returns_413():
    files = [
        {"path": f"app/f{i}.py", "content": "x"}
        for i in range(ingestion.MAX_ACCEPTED_FILES + 1)
    ]

    response = client.post("/projects", json={"files": files})

    assert response.status_code == 413
    assert "analysable files" in response.json()["detail"]


def test_project_too_large_in_total_returns_413():
    large = "x" * ingestion.MAX_CHARS_PER_FILE
    count = ingestion.MAX_CHARS_TOTAL // ingestion.MAX_CHARS_PER_FILE + 1
    files = [{"path": f"app/f{i}.py", "content": large} for i in range(count)]

    response = client.post("/projects", json={"files": files})

    assert response.status_code == 413


def test_a_refused_project_is_not_stored():
    huge = "x" * (ingestion.MAX_CHARS_PER_FILE + 1)
    client.post("/projects", json={"files": [{"path": "a.py", "content": huge}]})

    assert client.get("/projects").json() == []


# ------------------------------------------------------------------ reading


def test_the_list_starts_empty():
    response = client.get("/projects")

    assert response.status_code == 200
    assert response.json() == []


def test_the_list_contains_created_projects():
    client.post("/projects", json=SIMPLE_PROJECT)
    client.post("/projects", json=SIMPLE_PROJECT)

    assert len(client.get("/projects").json()) == 2


def test_fetch_one_project_by_id():
    created = client.post("/projects", json=SIMPLE_PROJECT).json()

    response = client.get(f"/projects/{created['project_id']}")

    assert response.status_code == 200
    assert response.json()["project_id"] == created["project_id"]


def test_unknown_id_returns_404():
    response = client.get("/projects/this-id-does-not-exist")

    assert response.status_code == 404
    assert response.json()["detail"] == "Project not found"


def test_two_projects_have_different_identifiers():
    first = client.post("/projects", json=SIMPLE_PROJECT).json()
    second = client.post("/projects", json=SIMPLE_PROJECT).json()

    assert first["project_id"] != second["project_id"]


# -------------------------------------------------------------- fingerprints


def test_two_identical_submissions_give_the_same_fingerprints():
    """Prepares the future cache: unchanged content = reusable analysis."""
    first = client.post("/projects", json=SIMPLE_PROJECT).json()
    second = client.post("/projects", json=SIMPLE_PROJECT).json()

    assert [f["hash"] for f in first["accepted_files"]] == [
        f["hash"] for f in second["accepted_files"]
    ]
