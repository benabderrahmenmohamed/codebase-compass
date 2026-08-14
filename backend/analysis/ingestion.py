"""Layer 1: receiving a submitted project.

This module turns a list of files sent by a client into a clean, bounded and
safe set.

Two principles:

1. **A path sent by the client is DATA, not truth.**
   A browser, a script or an attacker can send anything. Everything is
   re-validated here even if the frontend already filtered it.

2. **Allowlist, not blocklist.**
   We enumerate what is permitted, not what is forbidden. A blocklist always
   lets through whatever nobody thought of; an allowlist fails safe.

Like storage.py, this module knows nothing about HTTP: it raises a domain
exception and the router translates it into a 413.
"""

import hashlib
import re
from typing import NamedTuple

# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".php",
    ".go",
    ".rb",
}

# Dependency or build folders: never code written by the team.
IGNORED_FOLDERS = {
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".git",
    "dist",
    "build",
    "target",
    "vendor",
    "__pycache__",
    ".pytest_cache",
    ".tox",
    ".next",
    "site-packages",
    "coverage",
}

MAX_ACCEPTED_FILES = 200
MAX_CHARS_PER_FILE = 50_000
MAX_CHARS_TOTAL = 2_000_000

# Separate guard: we refuse to even look at an absurd submission before
# filtering. A folder containing node_modules can hold 40 000 entries; we
# want to ignore those, not fall over — but past this it is an attack.
MAX_SUBMITTED_ENTRIES = 5_000

# Reserved Windows names: a file called "NUL" or "COM1" cannot be created,
# which would break writing to disk further down the chain.
WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{n}" for n in range(1, 10)),
    *(f"lpt{n}" for n in range(1, 10)),
}

DRIVE_LETTER_PATTERN = re.compile(r"^[A-Za-z]:")


# --------------------------------------------------------------------------
# Output types
# --------------------------------------------------------------------------


class AcceptedFile(NamedTuple):
    path: str
    hash: str
    chars: int


class SkippedFile(NamedTuple):
    path: str
    reason: str


class IngestionResult(NamedTuple):
    accepted: list[AcceptedFile]
    skipped: list[SkippedFile]
    total_chars: int


class LimitExceeded(Exception):
    """A limit was exceeded: the whole submission is refused.

    Unlike a skipped file (which blocks nothing), an exceeded limit stops
    everything. The router translates this exception into a 413.
    """

    def __init__(self, limit: str, message: str, path: str | None = None):
        self.limit = limit
        self.path = path
        super().__init__(message)


# --------------------------------------------------------------------------
# Path checks
# --------------------------------------------------------------------------


def normalise(path: str) -> str:
    """Reduce a path to a single form before any check.

    Without this step "app\\main.py", "./app/main.py" and "app//main.py"
    would be three different paths for the same file — and a check that only
    recognises one form can be bypassed.
    """
    path = path.replace("\\", "/")
    while "//" in path:
        path = path.replace("//", "/")
    while path.startswith("./"):
        path = path[2:]
    return path.strip()


def is_suspicious_path(path: str) -> bool:
    """True if the path tries to escape the project.

    This is the protection against directory traversal: a path such as
    "../../etc/passwd" or "/etc/passwd" must be refused before anything
    touches the disk.
    """
    if not path:
        return True

    segments = path.split("/")

    # ".." as a whole SEGMENT, not as a substring: a file legitimately named
    # "..config.py" must not be wrongly refused.
    if ".." in segments:
        return True

    if path.startswith("/") or path.startswith("~"):
        return True

    if DRIVE_LETTER_PATTERN.match(path):  # C:/... or C:\...
        return True

    # Control characters: invisible, therefore perfect for fooling a visual
    # check or a log.
    if any(ord(c) < 32 for c in path):
        return True

    for segment in segments:
        if segment.split(".")[0].lower() in WINDOWS_RESERVED_NAMES:
            return True

    return False


def is_in_ignored_folder(path: str) -> bool:
    """True if any folder in the path is a dependency or build directory."""
    return any(segment in IGNORED_FOLDERS for segment in path.split("/")[:-1])


def has_allowed_extension(path: str) -> bool:
    """True if the file carries a code extension we know how to analyse."""
    name = path.split("/")[-1]
    if "." not in name:
        return False
    return "." + name.rsplit(".", 1)[-1].lower() in ALLOWED_EXTENSIONS


def fingerprint(content: str) -> str:
    """SHA-256 fingerprint of the content.

    Two uses: spotting two identical files within one project, and later
    skipping re-analysis of a file that has not changed between submissions.
    The same content always gives the same fingerprint; a single different
    character gives a completely different one.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Ingestion
# --------------------------------------------------------------------------


def prepare(files) -> IngestionResult:
    """Filter and validate submitted files.

    `files` is a sequence of objects with `.path` and `.content`
    (the ProjectFile models from schemas.py).

    A non-conforming file is SKIPPED, with its reason: a real project
    contains READMEs, images and configuration files, and refusing the whole
    submission because of them would be unusable.

    An exceeded limit raises LimitExceeded: there, everything stops.
    """
    if len(files) > MAX_SUBMITTED_ENTRIES:
        raise LimitExceeded(
            "submitted_entries",
            f"{len(files)} entries submitted, maximum {MAX_SUBMITTED_ENTRIES}.",
        )

    accepted: list[AcceptedFile] = []
    skipped: list[SkippedFile] = []
    total = 0
    seen: set[str] = set()

    for file in files:
        path = normalise(file.path)

        if is_suspicious_path(path):
            skipped.append(SkippedFile(file.path, "suspicious_path"))
            continue

        if is_in_ignored_folder(path):
            skipped.append(SkippedFile(path, "ignored_folder"))
            continue

        if not has_allowed_extension(path):
            skipped.append(SkippedFile(path, "unsupported_extension"))
            continue

        if path in seen:
            skipped.append(SkippedFile(path, "duplicate"))
            continue

        size = len(file.content)

        if size > MAX_CHARS_PER_FILE:
            raise LimitExceeded(
                "chars_per_file",
                f"File '{path}' is {size} characters, "
                f"maximum {MAX_CHARS_PER_FILE}.",
                path,
            )

        if total + size > MAX_CHARS_TOTAL:
            raise LimitExceeded(
                "chars_total",
                f"The project exceeds {MAX_CHARS_TOTAL} characters in total "
                f"(reached while adding '{path}').",
                path,
            )

        if len(accepted) >= MAX_ACCEPTED_FILES:
            raise LimitExceeded(
                "file_count",
                f"More than {MAX_ACCEPTED_FILES} analysable files "
                f"(reached at '{path}').",
                path,
            )

        # Empty files are KEPT: an empty __init__.py is empty by necessity,
        # and it carries structural information.
        seen.add(path)
        total += size
        accepted.append(AcceptedFile(path, fingerprint(file.content), size))

    return IngestionResult(accepted, skipped, total)
