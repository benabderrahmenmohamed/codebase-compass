"""Layer 0b: fetching a public GitHub repository.

The folder picker asks the user to have the code on their machine already.
This module removes that requirement: paste a repository reference, get the
same list of files the picker would have produced.

It ends where ingestion begins. `fetch_repo` returns objects carrying
`.path` and `.content` — exactly what `ingestion.prepare` consumes — so
every layer after this one is unchanged and cannot tell the difference.

Three decisions carry the safety of this module:

1. **We never fetch a URL the user gave us.**
   Accepting an arbitrary URL and requesting it is server-side request
   forgery: the caller supplies `http://localhost:8000/admin`, or a cloud
   provider's credential endpoint, and the server obligingly reads it. Here
   the input is parsed down to an OWNER and a REPO, each validated against a
   strict pattern, and the URL is then built by us against a fixed host. A
   reference that is not a GitHub repository is refused before any request.

2. **We never download an archive.**
   The tarball endpoint would bring back Zip Slip and tar traversal — an
   entry named `../../etc/passwd` escaping the extraction directory — which
   is the exact class of bug the project refuses ZIP uploads to avoid. The
   Git Trees API lists every path and size WITHOUT any content, so the
   allowlist, the ignore list and the size caps are applied to a list of
   names. Only survivors are fetched, one file at a time, by path.

3. **We reuse ingestion's rules rather than restating them.**
   The browser filters, this module filters, and the server filters again.
   Three enforcement points, one policy — because a second copy of the
   rules is a second thing to forget to update.

A note on rate limits. Content is read from raw.githubusercontent.com, not
from the REST contents endpoint. The REST endpoint charges one rate-limit
unit per file, so a 200-file repository would exhaust the unauthenticated
allowance of 60 requests an hour on a single analysis. The raw host does not
draw on that allowance, which means one analysis costs TWO API requests —
the metadata call and the tree call — no matter how many files it reads.
"""

import re
from concurrent.futures import ThreadPoolExecutor
from typing import NamedTuple

from analysis import ingestion

API_BASE = "https://api.github.com"
RAW_BASE = "https://raw.githubusercontent.com"

REQUEST_TIMEOUT_SECONDS = 15.0

# Files are independent, so they are fetched in parallel. Kept deliberately
# small: this is someone else's server, and politeness is also what keeps us
# below their abuse thresholds.
FETCH_WORKERS = 8

# A repository can hold far more entries than we will ever analyse. This
# bounds the work done on the LISTING, before any filtering.
MAX_TREE_ENTRIES = 20_000

# GitHub's own naming rules, tightened. Anything outside this is not a
# repository reference and is refused rather than guessed at.
OWNER_PATTERN = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})"
REPO_PATTERN = r"[A-Za-z0-9._-]{1,100}"

# Each alternative anchors the host with ^, so "https://evil.com/github.com/
# a/b" cannot match. Ordering matters: the most specific form first.
_REFERENCE_FORMS = (
    # https://github.com/owner/repo/tree/branch
    re.compile(
        rf"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>{OWNER_PATTERN})/"
        rf"(?P<repo>{REPO_PATTERN}?)(?:\.git)?/tree/(?P<ref>[^/\s]+)/?$"
    ),
    # https://github.com/owner/repo
    re.compile(
        rf"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>{OWNER_PATTERN})/"
        rf"(?P<repo>{REPO_PATTERN}?)(?:\.git)?/?$"
    ),
    # git@github.com:owner/repo.git
    re.compile(
        rf"^git@github\.com:(?P<owner>{OWNER_PATTERN})/"
        rf"(?P<repo>{REPO_PATTERN}?)(?:\.git)?/?$"
    ),
    # owner/repo
    re.compile(rf"^(?P<owner>{OWNER_PATTERN})/(?P<repo>{REPO_PATTERN}?)(?:\.git)?/?$"),
)


class RepoRef(NamedTuple):
    """A validated repository reference. Never holds a user-supplied URL."""

    owner: str
    repo: str
    ref: str | None = None  # branch or tag; None means the default branch

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"


class RemoteFile(NamedTuple):
    """One fetched file.

    Deliberately shaped like schemas.ProjectFile: `ingestion.prepare` reads
    `.path` and `.content` and needs to know nothing else.
    """

    path: str
    content: str


class GitHubResult(NamedTuple):
    """What came back, or a clear statement of why nothing did."""

    files: list[RemoteFile]
    skipped: list[ingestion.SkippedFile]
    available: bool
    reason: str | None = None
    ref: RepoRef | None = None
    resolved_ref: str | None = None
    listed: int = 0
    truncated: bool = False

    @property
    def is_complete(self) -> bool:
        """False when the listing itself was cut short by GitHub.

        A truncated tree means files exist that we never even saw, which is
        different from files we saw and skipped. The report has to be able
        to say which happened.
        """
        return self.available and not self.truncated


# Failures worth trying again: the request was fine, the moment was not.
RETRYABLE_REASONS = frozenset({"rate_limited", "network_error", "timeout", "github_error:502", "github_error:503"})


def parse_repo(reference: str) -> RepoRef | None:
    """Turn user input into a validated owner/repo, or None.

    Accepts the forms people actually paste: a browser URL, a URL with a
    branch, an SSH remote, or the bare `owner/repo`. Everything else —
    including a URL on any other host — returns None, and the caller
    refuses the request. This is the whole SSRF defence: after this
    function there is no user-controlled URL left in the system.
    """
    if not reference:
        return None

    text = reference.strip()
    for pattern in _REFERENCE_FORMS:
        match = pattern.match(text)
        if match:
            groups = match.groupdict()
            repo = groups["repo"]
            # "repo.git" is matched non-greedily above, but a bare
            # "owner/repo.git" still arrives with the suffix attached.
            if repo.endswith(".git"):
                repo = repo[: -len(".git")]
            if not repo:
                return None
            return RepoRef(groups["owner"], repo, groups.get("ref"))
    return None


def _headers(token: str | None) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        # GitHub asks for a User-Agent and answers 403 without one.
        "User-Agent": "codebase-compass",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _classify_status(status_code: int, body: dict | None) -> str:
    """Turn an HTTP status into a stable reason string."""
    if status_code == 404:
        # GitHub answers 404 rather than 403 for a private repository, so
        # that its existence is not revealed. We cannot tell the two apart
        # and must not claim to.
        return "not_found"
    if status_code in (403, 429):
        message = ((body or {}).get("message") or "").lower()
        if "rate limit" in message or status_code == 429:
            return "rate_limited"
        return "forbidden"
    if status_code == 451:
        return "unavailable_for_legal_reasons"
    return f"github_error:{status_code}"


def _get_json(client, url: str, token: str | None):
    """One GET returning parsed JSON, plus the response, never raising."""
    response = client.get(url, headers=_headers(token), timeout=REQUEST_TIMEOUT_SECONDS)
    try:
        body = response.json()
    except ValueError:
        body = None
    return response, body


def fetch_repo(reference: str, token: str | None = None, client=None) -> GitHubResult:
    """Fetch the analysable files of a public GitHub repository.

    Never raises: every failure returns a GitHubResult that says what went
    wrong, so the caller can report a cause rather than an empty result.

    Pass `client` (an httpx.Client) to inject a fake in tests; otherwise one
    is created and closed here.
    """
    ref = parse_repo(reference)
    if ref is None:
        return GitHubResult([], [], False, "invalid_reference")

    try:
        import httpx
    except ImportError:  # pragma: no cover - httpx is a direct dependency
        return GitHubResult([], [], False, "http_client_missing", ref)

    owned_client = client is None
    client = client or httpx.Client(follow_redirects=True)
    try:
        return _fetch(client, ref, token, httpx)
    except Exception as error:  # noqa: BLE001 - any failure degrades visibly
        return GitHubResult([], [], False, _classify_exception(error, httpx), ref)
    finally:
        if owned_client:
            client.close()


def _classify_exception(error: BaseException, httpx) -> str:
    # TimeoutException is a subclass of TransportError, so it is checked
    # first — the other order reports every timeout as a network error.
    if isinstance(error, httpx.TimeoutException):
        return "timeout"
    if isinstance(error, httpx.TransportError):
        return "network_error"
    return f"fetch_error:{type(error).__name__}"


def _fetch(client, ref: RepoRef, token: str | None, httpx) -> GitHubResult:
    # --- 1. metadata: does it exist, and what is the default branch? ------
    response, body = _get_json(client, f"{API_BASE}/repos/{ref.owner}/{ref.repo}", token)
    if response.status_code != 200:
        return GitHubResult([], [], False, _classify_status(response.status_code, body), ref)

    resolved = ref.ref or (body or {}).get("default_branch")
    if not resolved:
        # A repository with no commits has no default branch.
        return GitHubResult([], [], False, "empty_repository", ref)

    # --- 2. the tree: every path and size, no content --------------------
    tree_url = f"{API_BASE}/repos/{ref.owner}/{ref.repo}/git/trees/{resolved}?recursive=1"
    response, body = _get_json(client, tree_url, token)
    if response.status_code != 200:
        reason = _classify_status(response.status_code, body)
        # A bad branch name is a 404 on this call but the repository does
        # exist, so saying "not found" would send the user hunting for the
        # wrong problem.
        if reason == "not_found" and ref.ref:
            reason = "ref_not_found"
        return GitHubResult([], [], False, reason, ref, resolved)

    entries = (body or {}).get("tree") or []
    truncated = bool((body or {}).get("truncated"))
    if len(entries) > MAX_TREE_ENTRIES:
        entries = entries[:MAX_TREE_ENTRIES]
        truncated = True

    # --- 3. filter on names and sizes, before fetching anything ----------
    wanted, skipped = _select(entries)

    if not wanted:
        return GitHubResult(
            [], skipped, False, "no_analysable_files", ref, resolved, len(entries), truncated
        )

    # --- 4. fetch only the survivors -------------------------------------
    files, failed = _download(client, ref, resolved, wanted, token, httpx)
    skipped.extend(failed)

    if not files:
        return GitHubResult(
            [], skipped, False, "no_files_readable", ref, resolved, len(entries), truncated
        )

    return GitHubResult(files, skipped, True, None, ref, resolved, len(entries), truncated)


def _select(entries) -> tuple[list[str], list[ingestion.SkippedFile]]:
    """Choose what to download, using ingestion's own rules.

    Unlike `ingestion.prepare`, an oversized file or an over-long list is
    SKIPPED here rather than refusing the whole submission. A user who pastes
    a repository did not choose its contents, so one large vendored file must
    not cost them the entire analysis — whereas someone uploading a folder
    picked exactly what they sent, and a hard limit tells them so.
    """
    wanted: list[str] = []
    skipped: list[ingestion.SkippedFile] = []
    total = 0

    for entry in entries:
        if entry.get("type") != "blob":
            continue

        raw_path = entry.get("path") or ""
        path = ingestion.normalise(raw_path)

        if ingestion.is_suspicious_path(path):
            skipped.append(ingestion.SkippedFile(raw_path, "suspicious_path"))
            continue
        if ingestion.is_in_ignored_folder(path):
            skipped.append(ingestion.SkippedFile(path, "ignored_folder"))
            continue
        if not ingestion.has_allowed_extension(path):
            skipped.append(ingestion.SkippedFile(path, "unsupported_extension"))
            continue

        # `size` is bytes and our cap is characters. They differ only for
        # non-ASCII text, and always in the safe direction: bytes >= chars,
        # so nothing above the cap slips through.
        size = entry.get("size") or 0
        if size > ingestion.MAX_CHARS_PER_FILE:
            skipped.append(ingestion.SkippedFile(path, "file_too_large"))
            continue

        if len(wanted) >= ingestion.MAX_ACCEPTED_FILES:
            skipped.append(ingestion.SkippedFile(path, "too_many_files"))
            continue

        if total + size > ingestion.MAX_CHARS_TOTAL:
            skipped.append(ingestion.SkippedFile(path, "project_too_large"))
            continue

        total += size
        wanted.append(path)

    return wanted, skipped


def _download(client, ref: RepoRef, resolved: str, paths, token, httpx):
    """Read each chosen file from the raw host, in parallel."""
    from urllib.parse import quote

    def read(path: str):
        url = f"{RAW_BASE}/{ref.owner}/{ref.repo}/{quote(resolved)}/{quote(path)}"
        try:
            response = client.get(
                url, headers=_headers(token), timeout=REQUEST_TIMEOUT_SECONDS
            )
        except Exception:  # noqa: BLE001 - one bad file must not stop the rest
            return path, None, "fetch_failed"

        if response.status_code != 200:
            return path, None, "fetch_failed"

        text = response.text
        # A NUL byte means this is not text, whatever the extension claims.
        # Passing it on would break the parsers further down.
        if "\x00" in text:
            return path, None, "binary_file"
        return path, text, None

    files: list[RemoteFile] = []
    failed: list[ingestion.SkippedFile] = []

    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        for path, text, problem in pool.map(read, paths):
            if problem:
                failed.append(ingestion.SkippedFile(path, problem))
            else:
                files.append(RemoteFile(path, text))

    # Deterministic order: a dict of files should not depend on which
    # thread finished first.
    files.sort(key=lambda file: file.path)
    failed.sort(key=lambda file: file.path)
    return files, failed
