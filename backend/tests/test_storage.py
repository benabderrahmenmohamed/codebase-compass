"""Storage on SQLite.

The other test modules prove that nothing broke when this file changed —
they were written against the in-memory version and still pass untouched.
These tests prove the thing that is actually NEW: the data is still there
afterwards.
"""

from datetime import datetime, timezone

import pytest

import storage


@pytest.fixture(autouse=True)
def clean():
    storage.clear()
    yield
    storage.clear()


def an_analysis(analysis_id="a1", **extra):
    record = {
        "id": analysis_id,
        "language": "python",
        "scores": {
            "security": 12,
            "readability": 16,
            "maintainability": 14,
            "performance": 17,
            "best_practices": 15,
        },
        "total_score": 74,
        "issues": [{"line": 3, "severity": "critical", "message": "m", "suggestion": "s"}],
        "created_at": datetime(2026, 8, 24, 10, 0, tzinfo=timezone.utc),
    }
    record.update(extra)
    return record


def a_project(project_id="p1", **extra):
    record = {
        "project_id": project_id,
        "name": "demo",
        "source": "upload",
        "repo_url": None,
        "truncated": False,
        "accepted_files": [{"path": "main.py", "hash": "abc", "chars": 8}],
        "skipped": [],
        "total_chars": 8,
        "created_at": datetime(2026, 8, 24, 10, 0, tzinfo=timezone.utc),
        "_contents": {"main.py": "print(1)"},
    }
    record.update(extra)
    return record


# --------------------------------------------------------------------------
# The point of the change
# --------------------------------------------------------------------------


def test_an_analysis_survives_the_process_that_wrote_it():
    """A fresh connection is what a restarted server sees."""
    storage.save(an_analysis("a1"))

    # storage opens a connection per call, so this read is already a new
    # one — nothing is cached in the module.
    assert storage.get_by_id("a1") is not None


def test_a_project_and_its_file_contents_survive():
    """_contents is what the analysis layer needs; losing it loses the run."""
    storage.save_project(a_project("p1"))

    stored = storage.get_project_by_id("p1")
    assert stored["_contents"] == {"main.py": "print(1)"}


def test_an_unknown_id_is_none_not_an_error():
    assert storage.get_by_id("nope") is None
    assert storage.get_project_by_id("nope") is None


# --------------------------------------------------------------------------
# The round trip through text must be invisible
# --------------------------------------------------------------------------


def test_a_timestamp_comes_back_as_a_datetime_not_a_string():
    storage.save(an_analysis("a1"))
    assert isinstance(storage.get_by_id("a1")["created_at"], datetime)


def test_a_timestamp_keeps_its_value_and_timezone():
    original = datetime(2026, 8, 24, 10, 0, tzinfo=timezone.utc)
    storage.save(an_analysis("a1", created_at=original))
    assert storage.get_by_id("a1")["created_at"] == original


def test_nested_structures_come_back_unchanged():
    stored = an_analysis("a1")
    storage.save(stored)

    loaded = storage.get_by_id("a1")
    assert loaded["scores"] == stored["scores"]
    assert loaded["issues"] == stored["issues"]


def test_non_ascii_source_survives():
    """Submitted code is arbitrary text, and arbitrary text is not ASCII."""
    storage.save_project(a_project("p1", _contents={"a.py": "s = 'café → 日本'\n"}))
    assert storage.get_project_by_id("p1")["_contents"]["a.py"] == "s = 'café → 日本'\n"


def test_a_large_project_survives():
    big = {"f%d.py" % n: "x = 1\n" * 500 for n in range(50)}
    storage.save_project(a_project("p1", _contents=big))
    assert storage.get_project_by_id("p1")["_contents"] == big


# --------------------------------------------------------------------------
# Ordering and listing
# --------------------------------------------------------------------------


def test_analyses_are_returned_oldest_first():
    for index in range(5):
        storage.save(an_analysis(f"a{index}"))
    assert [a["id"] for a in storage.get_all()] == [f"a{i}" for i in range(5)]


def test_insertion_order_holds_even_for_identical_timestamps():
    """Ordering by created_at would tie here and shuffle between reads."""
    same = datetime(2026, 8, 24, 10, 0, tzinfo=timezone.utc)
    for index in range(5):
        storage.save(an_analysis(f"a{index}", created_at=same))

    first = [a["id"] for a in storage.get_all()]
    second = [a["id"] for a in storage.get_all()]
    assert first == second == [f"a{i}" for i in range(5)]


def test_projects_are_returned_oldest_first():
    for index in range(3):
        storage.save_project(a_project(f"p{index}"))
    assert [p["project_id"] for p in storage.get_all_projects()] == ["p0", "p1", "p2"]


def test_saving_the_same_id_twice_updates_rather_than_duplicates():
    storage.save(an_analysis("a1", total_score=10))
    storage.save(an_analysis("a1", total_score=90))

    assert len(storage.get_all()) == 1
    assert storage.get_by_id("a1")["total_score"] == 90


def test_the_caller_cannot_empty_the_store_by_mutating_a_result():
    storage.save(an_analysis("a1"))
    storage.get_all().clear()
    assert len(storage.get_all()) == 1


def test_clear_empties_both_tables():
    storage.save(an_analysis("a1"))
    storage.save_project(a_project("p1"))

    storage.clear()

    assert storage.get_all() == []
    assert storage.get_all_projects() == []


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def test_the_database_path_is_read_from_the_environment_every_time(monkeypatch, tmp_path):
    """Captured at import, a test could never redirect it — the same trap
    that let a deleted API key come back from .env during test setup."""
    target = tmp_path / "elsewhere.db"
    monkeypatch.setenv("COMPASS_DB", str(target))

    storage.save(an_analysis("a1"))

    assert target.exists()
    assert storage.get_by_id("a1") is not None


def test_two_databases_do_not_see_each_other(monkeypatch, tmp_path):
    monkeypatch.setenv("COMPASS_DB", str(tmp_path / "one.db"))
    storage.save(an_analysis("only-in-one"))

    monkeypatch.setenv("COMPASS_DB", str(tmp_path / "two.db"))
    assert storage.get_by_id("only-in-one") is None
