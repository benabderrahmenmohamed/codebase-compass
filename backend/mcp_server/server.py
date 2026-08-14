"""MCP tools: what the model may ask for on its own initiative.

Without these, the model receives one fixed payload and that is the end of
it. With them it can say "line 41 mentions Session — show me db.py" and
fetch it. **The model decides what it needs**, which is the only reason MCP
earns its place here rather than being ceremony around a function call.

Every tool description says WHEN to call it, not just what it does. That is
measurably better at getting a model to reach for a tool at the right moment
than a description that only states the tool's purpose.

## Security

These tools are driven by a model, and a model's output is untrusted input.
Two rules follow:

1. **Nothing here touches the filesystem.** `read_file` is a dictionary
   lookup inside one stored project — not `open()`. A tool that opened a
   model-supplied path would be an arbitrary-file-read vulnerability
   reachable by prompt injection.
2. **Everything is scoped to one project id.** A model cannot reach across
   projects, and cannot reach anything that was never submitted.
"""

from typing import Any

import storage
from analysis import semgrep_runner, skeleton
from analysis.context import DEFAULT_RADIUS

MAX_WINDOW_RADIUS = 60
MAX_SEARCH_RESULTS = 50
MAX_SNIPPET_CHARS = 50_000


def _contents(project_id: str) -> dict[str, str] | None:
    """The stored files of one project, or None if there is no such project."""
    project = storage.get_project_by_id(project_id)
    if project is None:
        return None
    return project.get("_contents", {})


# --------------------------------------------------------------------------
# The tools, as plain functions so they can be tested without a protocol
# --------------------------------------------------------------------------


def list_files(project_id: str) -> dict[str, Any]:
    """Every analysable file in a project, with its size."""
    contents = _contents(project_id)
    if contents is None:
        return {"error": "unknown_project", "project_id": project_id}

    return {
        "project_id": project_id,
        "files": [
            {"path": path, "lines": len(content.splitlines())}
            for path, content in sorted(contents.items())
        ],
    }


def get_skeleton(project_id: str) -> dict[str, Any]:
    """The project map: files, imports, entry points, signatures."""
    contents = _contents(project_id)
    if contents is None:
        return {"error": "unknown_project", "project_id": project_id}

    built = skeleton.build(contents)
    return {
        "entry_points": built.entry_points,
        "external_dependencies": built.external_dependencies,
        "reading_order": skeleton.reading_order(built),
        "files": [
            {
                "path": file.path,
                "lines": file.lines,
                "imports": built.imports_graph.get(file.path, []),
                "imported_by": built.imported_by.get(file.path, []),
                "symbols": [
                    {
                        "kind": symbol.kind,
                        "name": symbol.name,
                        "line": symbol.line,
                        "signature": symbol.signature,
                        "doc": symbol.doc,
                    }
                    for symbol in file.symbols
                ],
                "parse_error": file.parse_error,
            }
            for file in built.files
        ],
    }


def read_file(project_id: str, path: str) -> dict[str, Any]:
    """The full text of one file, with line numbers."""
    contents = _contents(project_id)
    if contents is None:
        return {"error": "unknown_project", "project_id": project_id}

    # A dictionary lookup, never a filesystem read: a path the model invented
    # simply misses, instead of reaching something it should not.
    content = contents.get(path)
    if content is None:
        return {
            "error": "unknown_file",
            "path": path,
            "available_files": sorted(contents)[:MAX_SEARCH_RESULTS],
        }

    lines = content.splitlines()
    numbered = "\n".join(f"{n:>5} | {line}" for n, line in enumerate(lines, start=1))
    return {"path": path, "lines": len(lines), "content": numbered}


def read_window(
    project_id: str, path: str, line: int, radius: int = DEFAULT_RADIUS
) -> dict[str, Any]:
    """A few lines around one line of one file."""
    contents = _contents(project_id)
    if contents is None:
        return {"error": "unknown_project", "project_id": project_id}

    content = contents.get(path)
    if content is None:
        return {"error": "unknown_file", "path": path}

    lines = content.splitlines()
    if not lines:
        return {"path": path, "start_line": 0, "end_line": 0, "content": ""}

    radius = max(0, min(radius, MAX_WINDOW_RADIUS))
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    if start > len(lines):
        return {"error": "line_out_of_range", "path": path, "file_lines": len(lines)}

    numbered = "\n".join(f"{n:>5} | {lines[n - 1]}" for n in range(start, end + 1))
    return {"path": path, "start_line": start, "end_line": end, "content": numbered}


def find_symbol(project_id: str, name: str) -> dict[str, Any]:
    """Where a function, class or constant is defined and where it is used."""
    contents = _contents(project_id)
    if contents is None:
        return {"error": "unknown_project", "project_id": project_id}

    built = skeleton.build(contents)

    definitions = [
        {"path": file.path, "line": symbol.line, "kind": symbol.kind, "signature": symbol.signature}
        for file in built.files
        for symbol in file.symbols
        if symbol.name == name or symbol.name.endswith(f".{name}")
    ]

    mentions = []
    for path, content in sorted(contents.items()):
        for number, text in enumerate(content.splitlines(), start=1):
            if name in text:
                mentions.append({"path": path, "line": number, "text": text.strip()[:120]})
                if len(mentions) >= MAX_SEARCH_RESULTS:
                    break
        if len(mentions) >= MAX_SEARCH_RESULTS:
            break

    return {"name": name, "definitions": definitions, "mentions": mentions}


def scan_snippet(code: str, language: str | None = None) -> dict[str, Any]:
    """Run the security rules over a piece of code that is not in a project."""
    if len(code) > MAX_SNIPPET_CHARS:
        return {"error": "too_large", "max_chars": MAX_SNIPPET_CHARS}

    result = semgrep_runner.scan(code, language)
    return {
        "available": result.available,
        "reason": result.reason,
        "findings": result.findings,
    }


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------

TOOLS = (
    (
        list_files,
        "List every analysable file in a project, with its line count. "
        "Call this first when you need to know what a project contains, "
        "before asking for any particular file.",
    ),
    (
        get_skeleton,
        "Get the project map: entry points, dependencies, a suggested reading "
        "order, and for each file its imports, importers and symbol "
        "signatures. Call this to orient yourself before reading any code — "
        "it is far cheaper than reading files one by one.",
    ),
    (
        read_file,
        "Read one whole file, with line numbers. Call this when the skeleton "
        "is not enough and you need to see how something is actually "
        "implemented. Prefer read_window when you only care about one place.",
    ),
    (
        read_window,
        "Read a few lines around a specific line of a specific file. Call "
        "this when a finding or a symbol points at a line and you need its "
        "immediate context to judge it — for example to work out what a "
        "badly named variable actually holds.",
    ),
    (
        find_symbol,
        "Find where a function, class or constant is defined and everywhere "
        "it is mentioned. Call this when you need to know what something is "
        "used for before judging its name, or to check whether code is dead.",
    ),
    (
        scan_snippet,
        "Run the security and best-practice rules over a piece of code that "
        "is not part of a stored project. Call this to check a snippet the "
        "user pasted, not to re-check code already analysed.",
    ),
)


def build_server(name: str = "code-quality"):
    """Create the MCP server with every tool registered.

    Built lazily so importing this module never requires the MCP SDK, and
    the FastAPI app keeps working on a machine that does not have it.
    """
    from mcp.server.fastmcp import FastMCP

    server = FastMCP(name)
    for function, description in TOOLS:
        server.add_tool(function, description=description)
    return server


def main() -> None:  # pragma: no cover - entry point
    """Run the server over stdio, the transport MCP clients expect."""
    build_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()
