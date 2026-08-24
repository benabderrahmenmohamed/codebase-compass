"""The GitHub source layer, tested entirely offline.

No test here touches the network: a fake client answers every request. The
suite's own socket guard would fail a test that tried, which is the point.
"""

import pytest

from analysis import github_source, ingestion


# --------------------------------------------------------------------------
# A fake httpx client
# --------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeClient:
    """Answers by URL. Records every URL it was asked for."""

    def __init__(self, routes, default=None):
        self.routes = routes
        self.default = default or FakeResponse(404, {"message": "Not Found"})
        self.requested = []

    def get(self, url, headers=None, timeout=None):
        self.requested.append(url)
        for fragment, response in self.routes.items():
            if fragment in url:
                if isinstance(response, Exception):
                    raise response
                return response
        return self.default

    def close(self):
        pass


def tree(*paths_and_sizes):
    return {
        "tree": [
            {"path": path, "type": "blob", "size": size}
            for path, size in paths_and_sizes
        ],
        "truncated": False,
    }


def repo_routes(entries, contents=None, default_branch="main"):
    routes = {
        "/repos/acme/widget/git/trees/": FakeResponse(200, entries),
        "/repos/acme/widget": FakeResponse(200, {"default_branch": default_branch}),
    }
    for path, text in (contents or {}).items():
        routes[f"/acme/widget/{default_branch}/{path}"] = FakeResponse(200, None, text)
    return routes


# --------------------------------------------------------------------------
# parse_repo — the SSRF boundary
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reference,expected",
    [
        ("owner/repo", ("owner", "repo", None)),
        ("https://github.com/owner/repo", ("owner", "repo", None)),
        ("http://github.com/owner/repo", ("owner", "repo", None)),
        ("https://www.github.com/owner/repo", ("owner", "repo", None)),
        ("https://github.com/owner/repo/", ("owner", "repo", None)),
        ("https://github.com/owner/repo.git", ("owner", "repo", None)),
        ("github.com/owner/repo", ("owner", "repo", None)),
        ("git@github.com:owner/repo.git", ("owner", "repo", None)),
        ("https://github.com/owner/repo/tree/develop", ("owner", "repo", "develop")),
        ("  owner/repo  ", ("owner", "repo", None)),
        ("owner/repo.with.dots", ("owner", "repo.with.dots", None)),
    ],
)
def test_accepted_reference_forms(reference, expected):
    assert github_source.parse_repo(reference) == github_source.RepoRef(*expected)


# Each of these is the reason the tool builds its own URL instead of
# fetching the one it was handed.
@pytest.mark.parametrize(
    "hostile",
    [
        "http://localhost:8000/admin",
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",  # cloud credentials
        "https://evil.com/github.com/owner/repo",
        "https://github.com.evil.com/owner/repo",
        "https://gitlab.com/owner/repo",
        "file:///etc/passwd",
        "owner/repo/../../etc/passwd",
        "not a repository",
        "",
        "   ",
        "/",
        "owner/",
        "/repo",
    ],
)
def test_anything_that_is_not_a_github_repo_is_refused(hostile):
    assert github_source.parse_repo(hostile) is None


def test_an_unparsable_reference_never_reaches_the_network():
    client = FakeClient({})
    result = github_source.fetch_repo("http://localhost:8000/admin", client=client)

    assert result.available is False
    assert result.reason == "invalid_reference"
    assert client.requested == []


# --------------------------------------------------------------------------
# Selection: filter on names and sizes, before downloading
# --------------------------------------------------------------------------


def test_only_analysable_files_are_downloaded():
    entries = tree(
        ("main.py", 100),
        ("README.md", 100),
        ("node_modules/react/index.js", 100),
        ("app/routes.py", 100),
    )
    client = FakeClient(
        repo_routes(entries, {"main.py": "a = 1", "app/routes.py": "b = 2"})
    )
    result = github_source.fetch_repo("acme/widget", client=client)

    assert [file.path for file in result.files] == ["app/routes.py", "main.py"]
    reasons = {skip.path: skip.reason for skip in result.skipped}
    assert reasons["README.md"] == "unsupported_extension"
    assert reasons["node_modules/react/index.js"] == "ignored_folder"


def test_ignored_folders_are_never_requested():
    entries = tree(("main.py", 10), ("node_modules/react/index.js", 10))
    client = FakeClient(repo_routes(entries, {"main.py": "a = 1"}))
    github_source.fetch_repo("acme/widget", client=client)

    assert not any("node_modules" in url for url in client.requested)


def test_a_file_over_the_size_cap_is_skipped_not_fetched():
    entries = tree(("big.py", ingestion.MAX_CHARS_PER_FILE + 1), ("ok.py", 5))
    client = FakeClient(repo_routes(entries, {"ok.py": "a = 1"}))
    result = github_source.fetch_repo("acme/widget", client=client)

    assert [file.path for file in result.files] == ["ok.py"]
    assert ("big.py", "file_too_large") in [(s.path, s.reason) for s in result.skipped]
    assert not any("big.py" in url for url in client.requested)


# An oversized file refuses the whole UPLOAD, because the user chose those
# files. It only skips here, because they did not choose the repository's
# contents.
def test_an_oversized_file_skips_rather_than_refusing_the_repository():
    entries = tree(("huge.py", 10_000_000), ("fine.py", 5))
    client = FakeClient(repo_routes(entries, {"fine.py": "a = 1"}))
    result = github_source.fetch_repo("acme/widget", client=client)

    assert result.available is True
    assert [file.path for file in result.files] == ["fine.py"]


def test_the_file_count_cap_is_reported_rather_than_silently_applied():
    entries = tree(*[(f"f{i}.py", 10) for i in range(ingestion.MAX_ACCEPTED_FILES + 5)])
    contents = {f"f{i}.py": "a = 1" for i in range(ingestion.MAX_ACCEPTED_FILES + 5)}
    client = FakeClient(repo_routes(entries, contents))
    result = github_source.fetch_repo("acme/widget", client=client)

    assert len(result.files) == ingestion.MAX_ACCEPTED_FILES
    assert sum(1 for s in result.skipped if s.reason == "too_many_files") == 5


def test_a_traversing_path_from_github_is_still_refused():
    # GitHub would not serve such a path, which is exactly why it must be
    # checked: trusting the source is how the check gets skipped.
    entries = tree(("../../etc/passwd.py", 10), ("safe.py", 10))
    client = FakeClient(repo_routes(entries, {"safe.py": "a = 1"}))
    result = github_source.fetch_repo("acme/widget", client=client)

    assert [file.path for file in result.files] == ["safe.py"]
    assert any(s.reason == "suspicious_path" for s in result.skipped)


def test_directories_in_the_tree_are_ignored():
    entries = {
        "tree": [
            {"path": "app", "type": "tree"},
            {"path": "app/main.py", "type": "blob", "size": 10},
        ],
        "truncated": False,
    }
    client = FakeClient(repo_routes(entries, {"app/main.py": "a = 1"}))
    result = github_source.fetch_repo("acme/widget", client=client)

    assert [file.path for file in result.files] == ["app/main.py"]


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------


def test_content_comes_from_the_raw_host_not_the_api():
    """Two API requests regardless of file count — see the module docstring."""
    entries = tree(("a.py", 5), ("b.py", 5))
    client = FakeClient(repo_routes(entries, {"a.py": "a = 1", "b.py": "b = 2"}))
    github_source.fetch_repo("acme/widget", client=client)

    api_calls = [url for url in client.requested if url.startswith(github_source.API_BASE)]
    raw_calls = [url for url in client.requested if url.startswith(github_source.RAW_BASE)]
    assert len(api_calls) == 2
    assert len(raw_calls) == 2


def test_the_branch_from_the_url_overrides_the_default():
    entries = tree(("a.py", 5))
    routes = {
        "/repos/acme/widget/git/trees/": FakeResponse(200, entries),
        "/repos/acme/widget": FakeResponse(200, {"default_branch": "main"}),
        "/acme/widget/develop/a.py": FakeResponse(200, None, "a = 1"),
    }
    client = FakeClient(routes)
    result = github_source.fetch_repo(
        "https://github.com/acme/widget/tree/develop", client=client
    )

    assert result.resolved_ref == "develop"
    assert result.available is True


def test_a_binary_file_is_skipped_not_passed_on():
    entries = tree(("logo.py", 10))
    routes = repo_routes(entries)
    routes["/acme/widget/main/logo.py"] = FakeResponse(200, None, "PNG\x00\x01binary")
    client = FakeClient(routes)
    result = github_source.fetch_repo("acme/widget", client=client)

    assert result.available is False
    assert result.reason == "no_files_readable"
    assert ("logo.py", "binary_file") in [(s.path, s.reason) for s in result.skipped]


def test_one_unreadable_file_does_not_lose_the_rest():
    entries = tree(("a.py", 5), ("b.py", 5))
    routes = repo_routes(entries, {"a.py": "a = 1"})
    routes["/acme/widget/main/b.py"] = FakeResponse(500, None, "")
    client = FakeClient(routes)
    result = github_source.fetch_repo("acme/widget", client=client)

    assert [file.path for file in result.files] == ["a.py"]
    assert ("b.py", "fetch_failed") in [(s.path, s.reason) for s in result.skipped]


def test_files_arrive_in_a_deterministic_order():
    entries = tree(("z.py", 5), ("a.py", 5), ("m.py", 5))
    contents = {"z.py": "z", "a.py": "a", "m.py": "m"}
    client = FakeClient(repo_routes(entries, contents))
    result = github_source.fetch_repo("acme/widget", client=client)

    assert [file.path for file in result.files] == ["a.py", "m.py", "z.py"]


def test_fetched_files_plug_straight_into_ingestion():
    """The whole point of the module: it ends where ingestion begins."""
    entries = tree(("main.py", 8))
    client = FakeClient(repo_routes(entries, {"main.py": "print(1)"}))
    result = github_source.fetch_repo("acme/widget", client=client)

    ingested = ingestion.prepare(result.files)
    assert [file.path for file in ingested.accepted] == ["main.py"]


# --------------------------------------------------------------------------
# Every failure states its cause
# --------------------------------------------------------------------------


def test_a_missing_or_private_repository_reports_not_found():
    client = FakeClient({"/repos/acme/widget": FakeResponse(404, {"message": "Not Found"})})
    result = github_source.fetch_repo("acme/widget", client=client)

    assert (result.available, result.reason) == (False, "not_found")


def test_a_rate_limit_is_distinguished_from_a_refusal():
    client = FakeClient(
        {"/repos/acme/widget": FakeResponse(403, {"message": "API rate limit exceeded"})}
    )
    assert github_source.fetch_repo("acme/widget", client=client).reason == "rate_limited"

    client = FakeClient({"/repos/acme/widget": FakeResponse(403, {"message": "Forbidden"})})
    assert github_source.fetch_repo("acme/widget", client=client).reason == "forbidden"


def test_a_bad_branch_is_not_reported_as_a_missing_repository():
    routes = {
        "/repos/acme/widget/git/trees/": FakeResponse(404, {"message": "Not Found"}),
        "/repos/acme/widget": FakeResponse(200, {"default_branch": "main"}),
    }
    client = FakeClient(routes)
    result = github_source.fetch_repo(
        "https://github.com/acme/widget/tree/nope", client=client
    )

    assert result.reason == "ref_not_found"


def test_a_repository_with_no_commits_says_so():
    client = FakeClient({"/repos/acme/widget": FakeResponse(200, {"default_branch": None})})
    assert github_source.fetch_repo("acme/widget", client=client).reason == "empty_repository"


def test_a_repository_with_no_code_says_so():
    entries = tree(("README.md", 10), ("logo.png", 10))
    client = FakeClient(repo_routes(entries))
    result = github_source.fetch_repo("acme/widget", client=client)

    assert (result.available, result.reason) == (False, "no_analysable_files")
    assert len(result.skipped) == 2


def test_a_timeout_is_not_reported_as_a_network_error():
    import httpx

    client = FakeClient({"/repos/acme/widget": httpx.ConnectTimeout("slow")})
    assert github_source.fetch_repo("acme/widget", client=client).reason == "timeout"

    client = FakeClient({"/repos/acme/widget": httpx.ConnectError("down")})
    assert github_source.fetch_repo("acme/widget", client=client).reason == "network_error"


def test_retryable_failures_are_marked_as_such():
    assert "rate_limited" in github_source.RETRYABLE_REASONS
    assert "timeout" in github_source.RETRYABLE_REASONS
    assert "not_found" not in github_source.RETRYABLE_REASONS
    assert "invalid_reference" not in github_source.RETRYABLE_REASONS


# A truncated listing means files exist that were never seen, which is not
# the same as files seen and skipped.
def test_a_truncated_listing_is_reported():
    entries = tree(("a.py", 5))
    entries["truncated"] = True
    client = FakeClient(repo_routes(entries, {"a.py": "a = 1"}))
    result = github_source.fetch_repo("acme/widget", client=client)

    assert result.available is True
    assert result.truncated is True
    assert result.is_complete is False


def test_an_enormous_listing_is_bounded_and_marked_truncated():
    entries = tree(*[(f"f{i}.py", 5) for i in range(github_source.MAX_TREE_ENTRIES + 10)])
    contents = {f"f{i}.py": "a = 1" for i in range(github_source.MAX_TREE_ENTRIES + 10)}
    client = FakeClient(repo_routes(entries, contents))
    result = github_source.fetch_repo("acme/widget", client=client)

    assert result.truncated is True
    assert result.listed == github_source.MAX_TREE_ENTRIES
