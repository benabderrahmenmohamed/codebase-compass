"""The snippet path, now running the same pipeline as a project.

`rule_engine.py` used to serve POST /analyses with its own regular-
expression rules and its own scoring model. Two engines meant two answers:
the same SQL injection scored 5 out of 20 for security through the project
pipeline and 12 through the snippet one. It also meant the snippet path
never received fixes made elsewhere — it kept matching SQL by looking for
a keyword and a plus sign on one line, which is exactly the rule that was
rewritten in taint mode after flagging a documentation example.

The tests below are mostly about AGREEMENT: the same code must produce the
same numbers whichever door it arrives through.
"""

import pytest
from fastapi.testclient import TestClient

import storage
from analysis import snippet
from main import app

client = TestClient(app)

UNSAFE = (
    "def get_user(uid):\n"
    '    q = "SELECT * FROM users WHERE id = " + uid\n'
    "    return db.execute(q)\n"
)

CATEGORIES = ("security", "readability", "maintainability", "performance", "best_practices")


@pytest.fixture(autouse=True)
def clean():
    storage.clear()
    yield
    storage.clear()


def analyse_as_snippet(code, language=None):
    return client.post("/analyses", json={"code": code, "language": language}).json()


def analyse_as_project(code, path="sample.py"):
    created = client.post("/projects", json={"files": [{"path": path, "content": code}]}).json()
    return client.post(
        f"/projects/{created['project_id']}/analysis?use_llm=false"
    ).json()


# --------------------------------------------------------------------------
# The point: one answer, not two
# --------------------------------------------------------------------------


def test_both_endpoints_give_the_same_scores():
    snippet_report = analyse_as_snippet(UNSAFE)
    project_report = analyse_as_project(UNSAFE)

    for category in CATEGORIES:
        assert snippet_report["scores"][category] == project_report["scores"][category]["score"], (
            f"{category} disagrees between the two endpoints"
        )


def test_both_endpoints_give_the_same_total():
    assert analyse_as_snippet(UNSAFE)["total_score"] == analyse_as_project(UNSAFE)["total_score"]


def test_security_is_driven_by_the_worst_finding_here_too():
    """The old engine subtracted penalties and reached 12. The project
    pipeline has always used the worst finding, which is 5 for critical."""
    assert analyse_as_snippet(UNSAFE)["scores"]["security"] == 5


def test_both_endpoints_find_the_same_number_of_problems():
    snippet_report = analyse_as_snippet(UNSAFE)
    project_report = analyse_as_project(UNSAFE)

    assert len(snippet_report["issues"]) == len(project_report["findings"])


# The fix that the snippet path never received, until now.
def test_sql_in_a_docstring_is_not_reported():
    """The old engine matched a SQL keyword plus a concatenation character
    on one line, and flagged documentation. Taint mode requires the value
    to reach an execution sink."""
    code = (
        "def helper():\n"
        '    """Example of what NOT to write:\n'
        '\n'
        '    query = "SELECT * FROM users WHERE id = " + user_id\n'
        '    """\n'
        "    return 1\n"
    )
    issues = analyse_as_snippet(code)["issues"]

    assert not any("injection" in issue["message"].lower() for issue in issues)


def test_a_real_injection_is_still_reported():
    """The other half: taint mode must not have made the rule useless."""
    issues = analyse_as_snippet(UNSAFE)["issues"]
    assert any("injection" in issue["message"].lower() for issue in issues)


# --------------------------------------------------------------------------
# Language detection, the one thing kept from the old engine
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code,expected",
    [
        ("def f():\n    import os\n    print(os)\n", "python"),
        ("const x = 1\nfunction f() { console.log(x) }\n", "javascript"),
        ("public class A { private void go() { System.out.println(1); } }", "java"),
        ("<?php echo $this->name; ?>", "php"),
    ],
)
def test_the_language_is_detected_from_the_code(code, expected):
    assert snippet.detect_language(code) == expected


def test_an_unrecognisable_snippet_is_unknown_rather_than_guessed():
    assert snippet.detect_language("hello world\n") == snippet.DEFAULT_LANGUAGE


def test_an_explicit_language_wins_over_detection():
    assert analyse_as_snippet("const x = 1\n", language="python")["language"] == "python"


# The detected language chooses the filename, and the filename is what tells
# the pipeline which detectors apply. That indirection is the whole design.
def test_the_language_selects_the_file_extension():
    assert snippet.filename_for("python").endswith(".py")
    assert snippet.filename_for("javascript").endswith(".js")
    assert snippet.filename_for("nonsense").endswith(".txt")


def test_a_python_snippet_gets_the_python_detectors():
    """Structural detectors are Python-only; a snippet must still reach
    them, which it only does if the synthetic filename is right."""
    code = (
        "def build(rows):\n"
        "    out = ''\n"
        "    for r in rows:\n"
        "        out += str(r)\n"
        "    return out\n"
    )
    issues = analyse_as_snippet(code)["issues"]

    assert any("String grown" in issue["message"] for issue in issues)


def test_a_javascript_snippet_gets_the_javascript_rules():
    code = (
        "export async function load(ids) {\n"
        "  for (const id of ids) {\n"
        "    await fetch(`/api/${id}`)\n"
        "  }\n"
        "}\n"
    )
    issues = analyse_as_snippet(code)["issues"]

    assert any("each iteration waits" in issue["message"] for issue in issues)


# --------------------------------------------------------------------------
# The contract did not move
# --------------------------------------------------------------------------


def test_the_response_shape_is_unchanged():
    body = analyse_as_snippet(UNSAFE)

    assert set(body) == {
        "id",
        "owner",
        "language",
        "scores",
        "total_score",
        "issues",
        "created_at",
    }
    assert set(body["scores"]) == set(CATEGORIES)


def test_every_issue_still_carries_the_four_declared_fields():
    for issue in analyse_as_snippet(UNSAFE)["issues"]:
        assert set(issue) == {"line", "severity", "message", "suggestion"}


def test_clean_code_still_scores_one_hundred():
    body = analyse_as_snippet("def add(first, second):\n    return first + second\n")

    assert body["total_score"] == 100
    assert body["issues"] == []


def test_the_legacy_engine_is_gone():
    """It served POST /analyses with a second scoring model. Leaving the
    module importable would invite it back."""
    with pytest.raises(ImportError):
        import rule_engine  # noqa: F401
