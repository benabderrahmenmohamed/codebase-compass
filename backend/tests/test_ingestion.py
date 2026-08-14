"""Tests of the ingestion layer.

These do not go through HTTP: they call the functions directly. That is
deliberate — a security rule must be verifiable without a server, and these
tests run in milliseconds.
"""

from typing import NamedTuple

import pytest

from analysis import ingestion


class F(NamedTuple):
    """A fake submitted file, with only what ingestion needs."""

    path: str
    content: str


# ---------------------------------------------------------------- happy path


def test_a_clean_project_is_fully_accepted():
    result = ingestion.prepare(
        [
            F("app/main.py", "print(1)"),
            F("app/models.py", "class C: pass"),
            F("front/index.js", "console.log(1)"),
        ]
    )

    assert len(result.accepted) == 3
    assert result.skipped == []
    assert result.total_chars == 8 + 13 + 14


def test_empty_files_are_kept():
    """An empty __init__.py carries structural information."""
    result = ingestion.prepare([F("app/__init__.py", "")])

    assert len(result.accepted) == 1
    assert result.accepted[0].chars == 0


# ------------------------------------------------------------- path traversal


@pytest.mark.parametrize(
    "path",
    [
        "../secret.py",
        "../../etc/passwd.py",
        "a/../../b.py",
        "/etc/passwd.py",
        "C:/Windows/system.py",
        "C:\\Windows\\system.py",
        "~/.ssh/id_rsa.py",
        "app/\x01strange.py",
        "",
    ],
)
def test_suspicious_paths_are_skipped(path):
    result = ingestion.prepare([F(path, "x = 1")])

    assert result.accepted == []
    assert result.skipped[0].reason == "suspicious_path"


def test_a_reserved_windows_name_is_skipped():
    """NUL, COM1... cannot exist as files on Windows."""
    result = ingestion.prepare([F("app/NUL.py", "x = 1")])

    assert result.skipped[0].reason == "suspicious_path"


def test_two_dots_inside_a_FILENAME_stay_accepted():
    """'..config.py' is a legitimate name: only the SEGMENT '..' is refused."""
    result = ingestion.prepare([F("app/..config.py", "x = 1")])

    assert len(result.accepted) == 1


# -------------------------------------------------------------- normalisation


def test_backslashes_are_normalised():
    result = ingestion.prepare([F("app\\routes\\api.py", "x = 1")])

    assert result.accepted[0].path == "app/routes/api.py"


def test_dot_slash_prefixes_are_removed():
    result = ingestion.prepare([F("./app//main.py", "x = 1")])

    assert result.accepted[0].path == "app/main.py"


# ------------------------------------------------------------------ filtering


@pytest.mark.parametrize("path", ["tool.exe", "archive.zip", "photo.png", "README"])
def test_unsupported_extensions_are_skipped(path):
    result = ingestion.prepare([F(path, "x")])

    assert result.accepted == []
    assert result.skipped[0].reason == "unsupported_extension"


@pytest.mark.parametrize(
    "path",
    [
        "node_modules/react/index.js",
        "backend/venv/lib/site.py",
        ".git/hooks/pre-commit.py",
        "frontend/dist/bundle.js",
        "app/__pycache__/main.py",
    ],
)
def test_dependency_folders_are_skipped(path):
    result = ingestion.prepare([F(path, "x = 1")])

    assert result.accepted == []
    assert result.skipped[0].reason == "ignored_folder"


def test_a_duplicate_path_is_kept_only_once():
    result = ingestion.prepare(
        [F("app/main.py", "version A"), F("./app/main.py", "version B")]
    )

    assert len(result.accepted) == 1
    assert result.skipped[0].reason == "duplicate"


def test_a_real_project_keeps_the_code_and_drops_the_rest():
    result = ingestion.prepare(
        [
            F("app/main.py", "x = 1"),
            F("README.md", "# project"),
            F("node_modules/lib/a.js", "x"),
            F("logo.png", "binary"),
            F("app/utils.py", "y = 2"),
        ]
    )

    assert [f.path for f in result.accepted] == ["app/main.py", "app/utils.py"]
    assert len(result.skipped) == 3


# --------------------------------------------------------------------- limits


def test_too_many_files():
    files = [F(f"app/f{i}.py", "x") for i in range(ingestion.MAX_ACCEPTED_FILES + 1)]

    with pytest.raises(ingestion.LimitExceeded) as error:
        ingestion.prepare(files)

    assert error.value.limit == "file_count"


def test_file_too_large():
    huge = "x" * (ingestion.MAX_CHARS_PER_FILE + 1)

    with pytest.raises(ingestion.LimitExceeded) as error:
        ingestion.prepare([F("app/huge.py", huge)])

    assert error.value.limit == "chars_per_file"
    # The message must say WHICH file is the problem.
    assert "app/huge.py" in str(error.value)


def test_project_too_large_in_total():
    large = "x" * ingestion.MAX_CHARS_PER_FILE
    count = ingestion.MAX_CHARS_TOTAL // ingestion.MAX_CHARS_PER_FILE + 1
    files = [F(f"app/f{i}.py", large) for i in range(count)]

    with pytest.raises(ingestion.LimitExceeded) as error:
        ingestion.prepare(files)

    assert error.value.limit == "chars_total"


def test_too_many_submitted_entries():
    files = [
        F(f"node_modules/f{i}.js", "x")
        for i in range(ingestion.MAX_SUBMITTED_ENTRIES + 1)
    ]

    with pytest.raises(ingestion.LimitExceeded) as error:
        ingestion.prepare(files)

    assert error.value.limit == "submitted_entries"


def test_a_folder_containing_node_modules_does_not_trip_the_limit():
    """The limit counts ACCEPTED files, not submitted ones.

    Otherwise a folder containing node_modules would be refused even though
    it only holds 2 analysable files.
    """
    files = [F(f"node_modules/p{i}/index.js", "x") for i in range(1000)]
    files += [F("app/main.py", "x = 1"), F("app/models.py", "y = 2")]

    result = ingestion.prepare(files)

    assert len(result.accepted) == 2
    assert len(result.skipped) == 1000


# ---------------------------------------------------------------- fingerprint


def test_the_same_content_gives_the_same_fingerprint():
    assert ingestion.fingerprint("print(1)") == ingestion.fingerprint("print(1)")


def test_different_content_gives_a_different_fingerprint():
    assert ingestion.fingerprint("print(1)") != ingestion.fingerprint("print(2)")


def test_the_fingerprint_is_a_sha256():
    value = ingestion.fingerprint("anything")

    assert len(value) == 64
    assert all(c in "0123456789abcdef" for c in value)


def test_two_identical_files_share_a_fingerprint():
    """Prepares the future cache: unchanged content = reusable result."""
    result = ingestion.prepare([F("app/a.py", "same code"), F("app/b.py", "same code")])

    assert result.accepted[0].hash == result.accepted[1].hash
