"""End-to-end tests of the project analysis endpoint.

The pipeline runs for real here — Semgrep included — with the LLM layer
switched off, so nothing costs money and nothing leaves the machine.
"""

import pytest
from fastapi.testclient import TestClient

import storage
from main import app

client = TestClient(app)

VULNERABLE = (
    "import hashlib\n\n"
    'API_TOKEN = "sk-live-abc123"\n\n\n'
    "def get_user(connection, user_id):\n"
    '    query = "SELECT * FROM users WHERE id = " + user_id\n'
    "    return connection.execute(query)\n\n\n"
    "def digest(text):\n"
    "    return hashlib.md5(text.encode()).hexdigest()\n"
)

PROJECT = {
    "name": "orders",
    "files": [
        {"path": "app/main.py", "content": "from app.db import fetch\n\n\ndef start():\n    return fetch()\n"},
        {"path": "app/db.py", "content": VULNERABLE},
        {"path": "app/models.py", "content": "class Order:\n    pass\n"},
    ],
}


@pytest.fixture(autouse=True)
def empty_storage():
    storage.clear()


def analyse(project=PROJECT):
    created = client.post("/projects", json=project).json()
    response = client.post(
        f"/projects/{created['project_id']}/analysis", params={"use_llm": False}
    )
    return response


# ---------------------------------------------------------------- the report


def test_analysis_returns_a_complete_report():
    response = analyse()

    assert response.status_code == 200
    report = response.json()
    assert set(report) >= {
        "project_id",
        "scores",
        "total_score",
        "grade",
        "entry_points",
        "reading_order",
        "files",
        "findings",
        "analysis_complete",
        "llm_used",
    }


def test_the_five_categories_are_all_scored():
    report = analyse().json()

    assert set(report["scores"]) == {
        "security",
        "readability",
        "maintainability",
        "performance",
        "best_practices",
    }


def test_the_vulnerable_file_drags_the_project_down():
    report = analyse().json()

    assert report["scores"]["security"]["score"] <= 5
    assert report["grade"] in ("D", "E")
    assert report["worst_file"] == "app/db.py"


def test_findings_carry_a_real_file_and_line():
    report = analyse().json()

    paths = {file["path"]: file["lines"] for file in report["files"]}
    assert report["findings"]
    for finding in report["findings"]:
        assert finding["path"] in paths
        assert 1 <= finding["line"] <= paths[finding["path"]]


def test_the_map_names_entry_points_and_a_reading_order():
    report = analyse().json()

    assert "app/main.py" in report["entry_points"]
    assert report["reading_order"]
    assert all(path in {f["path"] for f in report["files"]} for path in report["reading_order"])


def test_files_are_ordered_worst_first():
    report = analyse().json()

    scores = [file["total_score"] for file in report["files"]]
    assert scores == sorted(scores)


def test_each_file_reports_its_place_in_the_graph():
    report = analyse().json()
    db = next(file for file in report["files"] if file["path"] == "app/db.py")
    main = next(file for file in report["files"] if file["path"] == "app/main.py")

    assert main["is_entry_point"]
    assert "app/db.py" in main["imports"]
    assert "app/main.py" in db["imported_by"]


# ------------------------------------------------------- honest degradation


def test_the_report_says_the_llm_was_not_used():
    report = analyse().json()

    assert report["llm_used"] is False
    assert report["llm_reason"] == "disabled"
    assert report["explanations"] is None


def test_every_category_reports_how_far_it_looked():
    report = analyse().json()

    for category in report["scores"].values():
        assert category["coverage"] in (
            "evaluated",
            "partially_evaluated",
            "not_evaluated",
        )


def test_a_javascript_file_reports_performance_as_only_partly_evaluated():
    """A score of 20 must never be read as a clean bill of health.

    This asserted "not_evaluated" while the only performance detector
    was Python-only. The performance rule pack added JavaScript rules,
    so Semgrep now looks — but the AST metrics still do not, and the
    coverage flag says exactly that rather than rounding up.
    """
    report = analyse(
        {"files": [{"path": "front/app.js", "content": "const x = 1\n"}]}
    ).json()

    assert report["scores"]["performance"]["coverage"] == "partially_evaluated"


def test_what_was_dropped_is_counted():
    report = analyse().json()

    assert report["findings_dropped"] >= 0
    assert report["context_windows_dropped"] >= 0
    assert isinstance(report["analysis_complete"], bool)


# ------------------------------------------------------------- edge cases


def test_an_unknown_project_returns_404():
    response = client.post("/projects/does-not-exist/analysis")

    assert response.status_code == 404


def test_a_project_with_nothing_analysable_is_refused():
    """Scoring nothing would return a perfect 100 with nothing behind it."""
    created = client.post(
        "/projects",
        json={"files": [{"path": "README.md", "content": "# hello"}]},
    ).json()

    response = client.post(f"/projects/{created['project_id']}/analysis")

    assert response.status_code == 422
    assert "no analysable file" in response.json()["detail"]


def test_a_file_that_does_not_parse_does_not_break_the_report():
    report = analyse(
        {
            "files": [
                {"path": "app/broken.py", "content": "def f(:\n  ???\n"},
                {"path": "app/ok.py", "content": "def add(a, b):\n    return a + b\n"},
            ]
        }
    ).json()

    broken = next(f for f in report["files"] if f["path"] == "app/broken.py")
    assert broken["parse_error"] is not None
    assert report["total_score"] > 0


def test_analysis_is_deterministic():
    first = analyse().json()
    second = analyse().json()

    assert first["total_score"] == second["total_score"]
    assert first["grade"] == second["grade"]
    assert len(first["findings"]) == len(second["findings"])
