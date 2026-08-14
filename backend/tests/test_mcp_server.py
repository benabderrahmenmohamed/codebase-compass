"""Tests of the MCP tools.

The tools are plain functions, so almost everything is testable without the
protocol. One test checks that they really are registered with FastMCP.

The security tests matter most: these functions are driven by a model, and a
model's output is untrusted input. A tool that opened a model-supplied path
would be an arbitrary-file-read vulnerability reachable by prompt injection.
"""

import asyncio

import pytest

import storage
from mcp_server import server

PROJECT = {
    "app/main.py": (
        "from app.models import Order\n\n\n"
        "def start():\n"
        '    """Boot the app."""\n'
        "    return Order()\n"
    ),
    "app/models.py": "MAX_ITEMS = 50\n\n\nclass Order:\n    pass\n",
}


@pytest.fixture
def project_id():
    storage.clear()
    stored = storage.save_project(
        {
            "project_id": "proj-123",
            "name": "demo",
            "accepted_files": [],
            "skipped": [],
            "total_chars": 0,
            "created_at": None,
            "_contents": dict(PROJECT),
        }
    )
    yield stored["project_id"]
    storage.clear()


# ---------------------------------------------------------------- listing


def test_list_files_returns_every_file_with_its_size(project_id):
    result = server.list_files(project_id)

    assert [f["path"] for f in result["files"]] == ["app/main.py", "app/models.py"]
    assert result["files"][0]["lines"] == 6


def test_the_skeleton_carries_the_map_and_a_reading_order(project_id):
    result = server.get_skeleton(project_id)

    assert result["entry_points"] == ["app/main.py"]
    assert result["reading_order"]
    models = next(f for f in result["files"] if f["path"] == "app/models.py")
    assert "app/main.py" in models["imported_by"]
    assert {"class", "constant"} <= {s["kind"] for s in models["symbols"]}


# ---------------------------------------------------------------- reading


def test_read_file_numbers_the_lines(project_id):
    result = server.read_file(project_id, "app/models.py")

    assert "    1 | MAX_ITEMS = 50" in result["content"]
    assert result["lines"] == 5


def test_read_window_returns_only_the_surrounding_lines(project_id):
    result = server.read_window(project_id, "app/main.py", line=4, radius=1)

    assert result["start_line"] == 3
    assert result["end_line"] == 5
    assert "def start():" in result["content"]
    assert "from app.models" not in result["content"]


def test_a_window_stays_inside_the_file(project_id):
    result = server.read_window(project_id, "app/models.py", line=1, radius=50)

    assert result["start_line"] == 1
    assert result["end_line"] == 5


def test_an_absurd_radius_is_clamped(project_id):
    result = server.read_window(project_id, "app/main.py", line=3, radius=10_000)

    assert result["end_line"] <= 6


def test_a_line_past_the_end_of_the_file_is_refused(project_id):
    result = server.read_window(project_id, "app/models.py", line=900, radius=2)

    assert result["error"] == "line_out_of_range"


# ---------------------------------------------------------------- symbols


def test_find_symbol_reports_where_it_is_defined(project_id):
    result = server.find_symbol(project_id, "Order")

    definitions = result["definitions"]
    assert any(d["path"] == "app/models.py" and d["kind"] == "class" for d in definitions)


def test_find_symbol_reports_where_it_is_used(project_id):
    result = server.find_symbol(project_id, "Order")

    used_in = {m["path"] for m in result["mentions"]}
    assert used_in == {"app/main.py", "app/models.py"}


def test_a_symbol_nobody_uses_has_no_mentions_beyond_itself(project_id):
    result = server.find_symbol(project_id, "MAX_ITEMS")

    assert {m["path"] for m in result["mentions"]} == {"app/models.py"}


# ---------------------------------------------------------------- security


def test_a_tool_never_reads_the_filesystem(project_id, tmp_path):
    """The single most important property of this module.

    These functions are called by a model. If read_file used open(), a
    prompt-injected path would read anything the server process can reach.
    It is a dictionary lookup, so an invented path simply misses.
    """
    secret = tmp_path / "secret.txt"
    secret.write_text("SUPER SECRET", encoding="utf-8")

    for path in (
        str(secret),
        "../../etc/passwd",
        "/etc/passwd",
        "C:/Windows/System32/config/SAM",
        "app/../../../secret.txt",
    ):
        result = server.read_file(project_id, path)
        assert result["error"] == "unknown_file"
        assert "SUPER SECRET" not in str(result)


def test_a_window_cannot_escape_the_project_either(project_id):
    result = server.read_window(project_id, "../../etc/passwd", line=1)

    assert result["error"] == "unknown_file"


def test_tools_are_scoped_to_one_project():
    """A model must not be able to reach a project it was not given."""
    storage.clear()
    storage.save_project(
        {"project_id": "a", "_contents": {"a.py": "SECRET_A = 1\n"}}
    )
    storage.save_project(
        {"project_id": "b", "_contents": {"b.py": "SECRET_B = 2\n"}}
    )

    from_a = server.read_file("a", "b.py")
    from_b = server.read_file("b", "a.py")

    assert from_a["error"] == "unknown_file"
    assert from_b["error"] == "unknown_file"
    storage.clear()


def test_an_unknown_project_is_refused_by_every_tool():
    storage.clear()

    assert server.list_files("nope")["error"] == "unknown_project"
    assert server.get_skeleton("nope")["error"] == "unknown_project"
    assert server.read_file("nope", "a.py")["error"] == "unknown_project"
    assert server.read_window("nope", "a.py", 1)["error"] == "unknown_project"
    assert server.find_symbol("nope", "x")["error"] == "unknown_project"


def test_an_unknown_file_suggests_what_does_exist(project_id):
    """A model that guessed wrong should be able to correct itself."""
    result = server.read_file(project_id, "app/nope.py")

    assert "app/main.py" in result["available_files"]


def test_an_oversized_snippet_is_refused():
    result = server.scan_snippet("x" * (server.MAX_SNIPPET_CHARS + 1))

    assert result["error"] == "too_large"


# ---------------------------------------------------------------- snippets


def test_scanning_a_snippet_returns_findings():
    result = server.scan_snippet('PASSWORD = "admin123"\neval("1")\n', "python")

    assert result["available"]
    assert result["findings"]


# ------------------------------------------------------------ registration


def test_every_tool_is_registered_with_the_protocol():
    tools = asyncio.run(server.build_server().list_tools())

    names = {tool.name for tool in tools}
    assert names == {
        "list_files",
        "get_skeleton",
        "read_file",
        "read_window",
        "find_symbol",
        "scan_snippet",
    }


def test_every_description_says_when_to_call_the_tool():
    """A description that only says what a tool does gets it called less."""
    tools = asyncio.run(server.build_server().list_tools())

    for tool in tools:
        assert "Call this" in tool.description, tool.name


def test_the_schemas_are_generated_from_the_type_hints():
    tools = asyncio.run(server.build_server().list_tools())
    window = next(tool for tool in tools if tool.name == "read_window")

    properties = window.inputSchema["properties"]
    assert properties["line"]["type"] == "integer"
    assert set(window.inputSchema["required"]) == {"project_id", "path", "line"}
