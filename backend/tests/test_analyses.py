"""End-to-end tests of the analyses API.

TestClient calls the application directly, without going over the network:
no uvicorn needed to run these tests.

Every test follows the same three beats (Arrange / Act / Assert): prepare the
data, call the API, check the result.
"""

import pytest
from fastapi.testclient import TestClient

import storage
from main import app

client = TestClient(app)


CLEAN_CODE = """def add(first, second):
    return first + second
"""

VULNERABLE_CODE = """PASSWORD = "admin123"

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
"""


@pytest.fixture(autouse=True)
def empty_storage():
    """Empty the store before every test.

    autouse=True: applied automatically, no need to ask for it. Without it,
    tests would pollute each other and the result would depend on the order
    they ran in.
    """
    storage.clear()


# ---------------------------------------------------------------- health


def test_root_answers_ok():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


# ---------------------------------------------------------------- creation


def test_creation_returns_201_and_a_complete_report():
    response = client.post("/analyses", json={"code": CLEAN_CODE, "language": "python"})

    assert response.status_code == 201

    report = response.json()
    assert set(report) == {
        "id",
        "language",
        "scores",
        "total_score",
        "issues",
        "created_at",
    }
    assert report["language"] == "python"


def test_the_total_is_the_sum_of_the_five_scores():
    response = client.post("/analyses", json={"code": VULNERABLE_CODE})
    report = response.json()

    assert report["total_score"] == sum(report["scores"].values())


def test_every_score_is_between_0_and_20():
    response = client.post("/analyses", json={"code": VULNERABLE_CODE})

    for score in response.json()["scores"].values():
        assert 0 <= score <= 20


def test_two_analyses_have_different_identifiers():
    first = client.post("/analyses", json={"code": CLEAN_CODE}).json()
    second = client.post("/analyses", json={"code": CLEAN_CODE}).json()

    assert first["id"] != second["id"]


# ---------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "body",
    [
        {},  # the code field is missing
        {"code": ""},  # empty string
        {"code": "   "},  # whitespace only
    ],
)
def test_invalid_code_returns_422(body):
    """parametrize replays the same test with each value in the list."""
    response = client.post("/analyses", json=body)

    assert response.status_code == 422


def test_a_refused_submission_is_not_stored():
    client.post("/analyses", json={"code": ""})

    assert client.get("/analyses").json() == []


# ---------------------------------------------------------------- reading


def test_the_list_starts_empty():
    response = client.get("/analyses")

    assert response.status_code == 200
    assert response.json() == []


def test_the_list_contains_created_analyses():
    client.post("/analyses", json={"code": CLEAN_CODE})
    client.post("/analyses", json={"code": VULNERABLE_CODE})

    response = client.get("/analyses")

    assert len(response.json()) == 2


def test_fetch_one_analysis_by_id():
    created = client.post("/analyses", json={"code": CLEAN_CODE}).json()

    response = client.get(f"/analyses/{created['id']}")

    assert response.status_code == 200
    assert response.json()["id"] == created["id"]


def test_unknown_id_returns_404():
    response = client.get("/analyses/this-id-does-not-exist")

    assert response.status_code == 404
    assert response.json()["detail"] == "Analysis not found"


# ---------------------------------------------------------------- scoring


def test_clean_code_gets_the_maximum_score():
    report = client.post("/analyses", json={"code": CLEAN_CODE}).json()

    assert report["total_score"] == 100
    assert report["issues"] == []


def test_vulnerable_code_loses_security_points():
    report = client.post("/analyses", json={"code": VULNERABLE_CODE}).json()

    assert report["scores"]["security"] < 20
    severities = [issue["severity"] for issue in report["issues"]]
    assert "critical" in severities


def test_reported_lines_really_exist_in_the_code():
    """A problem reported on line 12 of a 5-line file is a bug.

    This is exactly the flaw of the first, fully frozen engine.
    """
    line_count = len(VULNERABLE_CODE.splitlines())

    report = client.post("/analyses", json={"code": VULNERABLE_CODE}).json()

    assert report["issues"], "vulnerable code must raise at least one problem"
    for issue in report["issues"]:
        assert 1 <= issue["line"] <= line_count


def test_two_different_inputs_give_different_results():
    """The flaw found during a demo: the same answer for any code."""
    clean = client.post("/analyses", json={"code": CLEAN_CODE}).json()
    vulnerable = client.post("/analyses", json={"code": VULNERABLE_CODE}).json()

    assert clean["total_score"] != vulnerable["total_score"]
    assert clean["issues"] != vulnerable["issues"]


def test_the_language_is_detected_when_not_supplied():
    javascript = "const token = 1\nfunction load() {\n  return token\n}\n"

    report = client.post("/analyses", json={"code": javascript}).json()

    assert report["language"] == "javascript"
