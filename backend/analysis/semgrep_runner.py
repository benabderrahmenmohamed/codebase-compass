"""Layer 1a: running Semgrep over submitted code.

Semgrep analyses the STRUCTURE of code (its syntax tree), not its text: an
`eval()` written inside a comment or a string is not reported.

Design rule: this module must NEVER break an analysis. Semgrep missing, too
slow, failing or unreadable -> we return an empty result flagged as
unavailable, and the metrics layer still produces a report.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

# The rules/ folder sits next to this file, one level up. Computing the path
# from __file__ means the server can be started from any working directory.
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

TIMEOUT_SECONDS = 10

# Bump this when rules change: it invalidates the whole cache.
RULES_VERSION = "2"

# Semgrep picks its parser from the file extension.
EXTENSIONS = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "php": ".php",
}
DEFAULT_EXTENSION = ".py"

# An unbounded cache is a memory leak, so we clear it past this size.
MAX_CACHE_ENTRIES = 200

_cache: dict[str, list[dict]] = {}


class SemgrepResult(NamedTuple):
    """The result of a scan, together with its status.

    Returning a bare empty list would be ambiguous: "no problem found" and
    "the scan could not run" would look identical. A user would then see
    20/20 for security on a broken installation.

    Degradation must always be VISIBLE: the report needs to be able to say
    "security analysis unavailable" rather than lie.

    NamedTuple: behaves like a tuple (`findings, ok, reason = scan(...)`)
    while still having named fields.
    """

    findings: list[dict]
    available: bool
    reason: str | None = None


# --------------------------------------------------------------------------
# Locating the executable
# --------------------------------------------------------------------------


def find_semgrep() -> str | None:
    """Return the path to the Semgrep executable, or None if not found.

    We look next to the running Python first: inside a virtual environment,
    semgrep.exe lives in the same Scripts/ folder. That is more reliable than
    PATH, which only contains that folder when the venv has been activated.
    """
    python_dir = Path(sys.executable).parent
    for name in ("semgrep.exe", "semgrep"):
        candidate = python_dir / name
        if candidate.exists():
            return str(candidate)

    return shutil.which("semgrep")


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


def _fingerprint(code: str, language: str | None) -> str:
    """A short unique identifier for a submission (SHA-256).

    The rules version is part of the fingerprint: changing a rule changes
    every fingerprint, so nothing stale is ever reused.
    """
    base = f"{RULES_VERSION}|{language or ''}|{code}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def clear_cache() -> None:
    """Empty the cache. Used by tests."""
    _cache.clear()


# --------------------------------------------------------------------------
# Converting Semgrep's format into ours
# --------------------------------------------------------------------------


def _convert(result: dict) -> dict:
    """Turn one Semgrep result into a finding in the project's format.

    The category / severity / penalty / suggestion fields come from the
    metadata WE wrote in rules/quality.yaml. Semgrep copies them through into
    its JSON output untouched.
    """
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})

    return {
        "line": result.get("start", {}).get("line", 1),
        "severity": metadata.get("severity", "medium"),
        "message": (extra.get("message") or "").strip(),
        "suggestion": metadata.get("suggestion", ""),
        "category": metadata.get("category", "best_practices"),
        "penalty": metadata.get("penalty", 3),
        "source": "semgrep",
        "rule": result.get("check_id", "").split(".")[-1],
    }


# --------------------------------------------------------------------------
# The scan
# --------------------------------------------------------------------------


def _run(target: str, cwd: str) -> subprocess.CompletedProcess:
    """Run Semgrep once over a file or a directory."""
    return subprocess.run(
        [
            find_semgrep(),
            "--experimental",  # native engine: about 6x faster
            "--config",
            str(RULES_DIR),
            "--json",
            "--quiet",
            "--metrics=off",  # no data sent to Semgrep
            target,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=TIMEOUT_SECONDS,
        cwd=cwd,
    )


def scan_project(contents: dict[str, str]) -> SemgrepResult:
    """Scan a whole project in ONE Semgrep run.

    Semgrep scans directories natively, so we write the project to a
    temporary tree and hand it the folder. One subprocess for 200 files
    instead of 200 — the difference between half a second and two minutes.

    Each finding carries the project-relative `path` it came from.
    """
    if not contents:
        return SemgrepResult([], True)

    key = _fingerprint("\0".join(f"{p}\0{c}" for p, c in sorted(contents.items())), None)
    if key in _cache:
        return SemgrepResult([dict(f) for f in _cache[key]], True)

    if find_semgrep() is None:
        return SemgrepResult([], False, "semgrep_missing")

    directory = tempfile.mkdtemp(prefix="code_quality_project_")
    root = Path(directory).resolve()
    try:
        for relative, content in contents.items():
            target = (root / relative).resolve()
            # Defence in depth: ingestion already rejected traversal, but
            # this is the moment something is written to disk, so we check
            # again rather than trust an earlier layer.
            if not target.is_relative_to(root):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        completed = _run(".", directory)
        if completed.returncode != 0:
            return SemgrepResult([], False, "execution_error")

        findings = []
        for result in json.loads(completed.stdout).get("results", []):
            finding = _convert(result)
            # Semgrep reports paths relative to its working directory.
            finding["path"] = result.get("path", "").replace("\\", "/").lstrip("./")
            findings.append(finding)

    except subprocess.TimeoutExpired:
        return SemgrepResult([], False, "timeout")
    except (OSError, ValueError, KeyError):
        return SemgrepResult([], False, "unreadable_output")
    finally:
        shutil.rmtree(directory, ignore_errors=True)

    if len(_cache) >= MAX_CACHE_ENTRIES:
        _cache.clear()
    _cache[key] = [dict(f) for f in findings]

    return SemgrepResult(findings, True)


def scan(code: str, language: str | None = None) -> SemgrepResult:
    """Scan code with Semgrep.

    Never raises: on any problem it returns an empty result with
    `available=False` and a reason, so the report can state that the
    analysis is incomplete.
    """
    key = _fingerprint(code, language)
    if key in _cache:
        # Copies: otherwise the caller could mutate the cache contents.
        return SemgrepResult([dict(f) for f in _cache[key]], True)

    semgrep = find_semgrep()
    if semgrep is None:
        return SemgrepResult([], False, "semgrep_missing")

    extension = EXTENSIONS.get((language or "").lower(), DEFAULT_EXTENSION)

    # Isolated directory, removed in the finally block whatever happens.
    directory = tempfile.mkdtemp(prefix="code_quality_")
    try:
        target = Path(directory) / f"submission{extension}"
        target.write_text(code, encoding="utf-8")

        completed = subprocess.run(
            [
                semgrep,
                "--experimental",  # native engine: about 6x faster
                "--config",
                str(RULES_DIR),
                "--json",
                "--quiet",
                "--metrics=off",  # no data sent to Semgrep
                str(target),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=TIMEOUT_SECONDS,
        )

        if completed.returncode != 0:
            return SemgrepResult([], False, "execution_error")

        findings = [
            _convert(result)
            for result in json.loads(completed.stdout).get("results", [])
        ]

    except subprocess.TimeoutExpired:
        return SemgrepResult([], False, "timeout")
    except (OSError, ValueError, KeyError):
        # ValueError covers json.JSONDecodeError and UnicodeDecodeError,
        # both of which inherit from it.
        return SemgrepResult([], False, "unreadable_output")
    finally:
        # Runs after a return as well as after an exception: the user's code
        # never stays on disk.
        shutil.rmtree(directory, ignore_errors=True)

    # Only successful scans are cached. A transient failure (a timeout on a
    # busy machine) must not be memorised: the next attempt should succeed.
    if len(_cache) >= MAX_CACHE_ENTRIES:
        _cache.clear()
    _cache[key] = [dict(f) for f in findings]

    return SemgrepResult(findings, True)
