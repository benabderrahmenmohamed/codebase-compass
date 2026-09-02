"""Layer 2: the project skeleton.

The skeleton is a compact map of a codebase: which files exist, what each one
declares, what imports what, and where execution starts. Function *bodies*
are deliberately excluded.

Why it matters: a 200-file project is hundreds of thousands of characters,
but its skeleton is a few thousand. We send the model the map, not the
territory — and it can ask for any specific file later through an MCP tool.

Python is parsed with the standard library's `ast` module, which builds a
syntax tree **without executing the code**. That is safe by construction:
analysing a malicious file cannot run it.

JavaScript and TypeScript use regular expressions for now — approximate but
dependency-free. tree-sitter is the upgrade path when it earns its place.
"""

import ast
import re
import sys
from typing import NamedTuple

PYTHON_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}

# Filenames that conventionally start a program.
ENTRY_POINT_NAMES = {
    "main.py",
    "app.py",
    "run.py",
    "manage.py",
    "wsgi.py",
    "asgi.py",
    "index.js",
    "main.js",
    "app.js",
    "server.js",
    "index.ts",
    "main.ts",
}

# Frameworks whose instantiation marks the application's starting point.
#
# These are matched against the syntax tree, never against raw text. Matching
# text would flag any file that merely *mentions* FastAPI — including a
# docstring example, a test fixture, or this very list. That mistake is
# exactly what this module exists to avoid.
FRAMEWORK_NAMES = {"FastAPI", "Flask", "express", "createServer"}


class Symbol(NamedTuple):
    """One thing a file declares: a function, a class, a constant."""

    kind: str  # "function" | "class" | "method" | "constant"
    name: str
    line: int
    signature: str
    doc: str | None


class FileSkeleton(NamedTuple):
    """What one file declares and depends on."""

    path: str
    language: str
    lines: int
    imports: list[str]  # raw module names, as written
    symbols: list[Symbol]
    is_entry_point: bool
    parse_error: str | None = None


class ProjectSkeleton(NamedTuple):
    """The whole project: files, dependency graph, entry points."""

    files: list[FileSkeleton]
    entry_points: list[str]
    imports_graph: dict[str, list[str]]  # path -> internal paths it imports
    imported_by: dict[str, list[str]]  # path -> paths that import it
    external_dependencies: list[str]  # third-party packages, sorted


# --------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------


def _signature(node) -> str:
    """Rebuild a readable signature without including the body."""
    try:
        arguments = ast.unparse(node.args)
    except Exception:  # pragma: no cover - defensive
        arguments = "..."
    returns = ""
    if node.returns is not None:
        try:
            returns = f" -> {ast.unparse(node.returns)}"
        except Exception:  # pragma: no cover - defensive
            returns = ""
    return f"{node.name}({arguments}){returns}"


def _first_doc_line(node) -> str | None:
    """The first line of a docstring: enough to say what something is for."""
    doc = ast.get_docstring(node)
    if not doc:
        return None
    return doc.strip().splitlines()[0]


def _has_main_guard(tree: ast.Module) -> bool:
    """True if the file contains `if __name__ == "__main__":`."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if isinstance(test, ast.Compare) and isinstance(test.left, ast.Name):
            if test.left.id == "__name__":
                return True
    return False


def _instantiates_framework(tree: ast.Module) -> bool:
    """True if the file actually CALLS a framework constructor.

    Walking the tree means a framework name written inside a string, a
    comment or a docstring is correctly ignored: only a real call counts.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (
            func.id
            if isinstance(func, ast.Name)
            else func.attr if isinstance(func, ast.Attribute) else None
        )
        if name in FRAMEWORK_NAMES:
            return True
    return False


def parse_python(path: str, content: str) -> FileSkeleton:
    """Extract the skeleton of a Python file using `ast`.

    A file that does not parse is not a failure: we record the error and keep
    going. Submitted code is often incomplete, and one broken file must not
    stop the analysis of the other 199.
    """
    line_count = len(content.splitlines())

    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError) as error:
        return FileSkeleton(
            path=path,
            language="python",
            lines=line_count,
            imports=[],
            symbols=[],
            is_entry_point=False,
            parse_error=f"{type(error).__name__}: {error}",
        )

    imports: list[str] = []
    symbols: list[Symbol] = []

    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)

        elif isinstance(node, ast.ImportFrom):
            # A relative import (level > 0) keeps its dots so the resolver
            # can work out what it points at.
            #
            # We record the MOST SPECIFIC form, module.name, because
            # `from analysis import ingestion` imports the submodule
            # analysis/ingestion.py — not the package's __init__.py. The
            # resolver walks back up when the specific form does not exist.
            prefix = "." * node.level
            module = node.module or ""
            for alias in node.names:
                parts = [part for part in (module, alias.name) if part]
                imports.append(prefix + ".".join(parts))

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.append(
                Symbol(
                    "function",
                    node.name,
                    node.lineno,
                    _signature(node),
                    _first_doc_line(node),
                )
            )

        elif isinstance(node, ast.ClassDef):
            symbols.append(
                Symbol("class", node.name, node.lineno, node.name, _first_doc_line(node))
            )
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    symbols.append(
                        Symbol(
                            "method",
                            f"{node.name}.{child.name}",
                            child.lineno,
                            _signature(child),
                            _first_doc_line(child),
                        )
                    )

        elif isinstance(node, ast.Assign):
            # Module-level constants: UPPER_CASE names carry configuration
            # and are often what a newcomer needs to find first.
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    symbols.append(
                        Symbol("constant", target.id, node.lineno, target.id, None)
                    )

    is_entry = (
        path.split("/")[-1] in ENTRY_POINT_NAMES
        or _has_main_guard(tree)
        or _instantiates_framework(tree)
    )

    return FileSkeleton(
        path=path,
        language="python",
        lines=line_count,
        imports=imports,
        symbols=symbols,
        is_entry_point=is_entry,
    )


# --------------------------------------------------------------------------
# JavaScript / TypeScript (approximate, regex-based)
# --------------------------------------------------------------------------

JS_IMPORT_PATTERNS = (
    re.compile(r"""^\s*import\s+[^'"]*from\s+['"]([^'"]+)['"]""", re.M),
    re.compile(r"""^\s*import\s+['"]([^'"]+)['"]""", re.M),
    re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""^\s*export\s+[^'"]*from\s+['"]([^'"]+)['"]""", re.M),
)

JS_SYMBOL_PATTERNS = (
    ("function", re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)", re.M)),
    ("class", re.compile(r"^\s*(?:export\s+)?class\s+(\w+)", re.M)),
    ("function", re.compile(r"^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(", re.M)),
    ("constant", re.compile(r"^\s*(?:export\s+)?const\s+([A-Z][A-Z0-9_]*)\s*=", re.M)),
)


def _line_of(content: str, position: int) -> int:
    """Convert a character offset into a 1-based line number."""
    return content.count("\n", 0, position) + 1


def parse_javascript(path: str, content: str) -> FileSkeleton:
    """Extract an approximate skeleton of a JS/TS file.

    Regular expressions cannot understand syntax, so this misses unusual
    forms. It is deliberately simple: dependency-free and good enough to draw
    the import map. tree-sitter replaces it when precision matters.
    """
    imports: list[str] = []
    for pattern in JS_IMPORT_PATTERNS:
        imports.extend(pattern.findall(content))

    symbols: list[Symbol] = []
    seen: set[tuple[str, str]] = set()
    for kind, pattern in JS_SYMBOL_PATTERNS:
        for match in pattern.finditer(content):
            name = match.group(1)
            if (kind, name) in seen:
                continue
            seen.add((kind, name))
            symbols.append(
                Symbol(kind, name, _line_of(content, match.start()), name, None)
            )

    symbols.sort(key=lambda symbol: symbol.line)

    # For JS we have no syntax tree, so we strip string literals before
    # looking for a framework call. Without that, "app = express()" written
    # inside a documentation string would count as a real entry point.
    code_only = re.sub(r"""(['"`])(?:\\.|(?!\1).)*\1""", "''", content)
    is_entry = path.split("/")[-1] in ENTRY_POINT_NAMES or any(
        re.search(rf"\b{name}\s*\(", code_only) for name in FRAMEWORK_NAMES
    )

    return FileSkeleton(
        path=path,
        language="javascript",
        lines=len(content.splitlines()),
        imports=imports,
        symbols=symbols,
        is_entry_point=is_entry,
    )


# --------------------------------------------------------------------------
# Resolving imports to files inside the project
# --------------------------------------------------------------------------


def module_name(path: str) -> str:
    """Turn a Python file path into its dotted module name.

    app/models.py      -> app.models
    app/__init__.py    -> app
    """
    stem = path[:-3] if path.endswith(".py") else path
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    return stem.replace("/", ".")


def python_module_map(files) -> dict[str, str]:
    """Map every dotted module name a project file can answer to.

    A file tree does not say where Python's import root is, and assuming it
    is the project root is wrong for most real repositories. Submitting the
    `backend/` folder gives `analysis/skeleton.py`, so `from analysis import
    ingestion` resolves. Fetching the whole repository gives
    `backend/analysis/skeleton.py`, the same import resolves to nothing, and
    every internal module is then reported as a third-party dependency —
    which is how `storage`, `schemas` and `routers` came to be listed
    alongside `fastapi` and `pydantic`.

    So shorter names are registered as well: `backend.analysis.skeleton`
    also answers to `analysis.skeleton` and to `skeleton`.

    When two files claim the same shortened name, the SHALLOWEST wins —
    because that is what Python itself does. With `backend/` on the path,
    `import notifications` finds `backend/notifications.py`, not
    `backend/routers/notifications.py`; the second is only reachable as
    `routers.notifications`. Preferring depth is not a tie-break heuristic,
    it is the actual import rule.

    Only a genuine tie — two files at the same depth, such as
    `a/util.py` and `b/util.py` — is left unregistered, so the import
    stays unresolved rather than being attached to whichever file happened
    to be parsed first. An unresolved import is visible; a confidently
    wrong edge in the graph is not.

    An earlier version stopped at "ambiguous, give up", which was safe and
    still wrong in its consequence: `notifications` went unresolved and was
    then reported to the user as a third-party dependency, alongside fastapi
    and pydantic. Found by reading the tool's own output on its own
    repository.
    """
    full: dict[str, str] = {}
    claims: dict[str, set[str]] = {}

    for file in files:
        if file.language != "python":
            continue
        name = module_name(file.path)
        full[name] = file.path
        parts = name.split(".")
        for start in range(1, len(parts)):
            claims.setdefault(".".join(parts[start:]), set()).add(file.path)

    # A full path always wins over a shortened one.
    resolved = dict(full)
    for name, paths in claims.items():
        if name in resolved:
            continue

        by_depth: dict[int, list[str]] = {}
        for path in paths:
            by_depth.setdefault(path.count("/"), []).append(path)

        shallowest = by_depth[min(by_depth)]
        if len(shallowest) == 1:
            resolved[name] = shallowest[0]

    return resolved


def _resolve_python(raw: str, from_path: str, modules: dict[str, str]) -> str | None:
    """Find which project file a Python import refers to, if any."""
    if raw.startswith("."):
        # Relative import: count the leading dots to know how far up to go.
        level = len(raw) - len(raw.lstrip("."))
        suffix = raw.lstrip(".")

        parts = module_name(from_path).split(".")
        # The package of a module is its path minus the module itself,
        # except for a package's own __init__.py.
        package = parts if from_path.endswith("/__init__.py") else parts[:-1]
        base = package[: len(package) - (level - 1)] if level > 1 else package

        full = ".".join([*base, suffix]) if suffix else ".".join(base)
    else:
        full = raw

    # `from app.models import Order` imports the module app.models; but
    # `import app.models.thing` may point at a symbol, so we walk back up.
    candidate = full
    while candidate:
        if candidate in modules:
            return modules[candidate]
        if "." not in candidate:
            return None
        candidate = candidate.rsplit(".", 1)[0]
    return None


def _resolve_javascript(raw: str, from_path: str, known: set[str]) -> str | None:
    """Find which project file a JS import refers to, if any."""
    if not raw.startswith("."):
        return None  # a package, not a project file

    base_parts = from_path.split("/")[:-1]
    for part in raw.split("/"):
        if part == ".":
            continue
        if part == "..":
            if base_parts:
                base_parts.pop()
            continue
        base_parts.append(part)

    target = "/".join(base_parts)
    candidates = [
        target,
        *(f"{target}{ext}" for ext in (".js", ".jsx", ".ts", ".tsx")),
        *(f"{target}/index{ext}" for ext in (".js", ".jsx", ".ts", ".tsx")),
    ]
    for candidate in candidates:
        if candidate in known:
            return candidate
    return None


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------


def _language_of(path: str) -> str | None:
    suffix = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if suffix in PYTHON_EXTENSIONS:
        return "python"
    if suffix in JS_EXTENSIONS:
        return "javascript"
    return None


def build(contents: dict[str, str]) -> ProjectSkeleton:
    """Build the skeleton of a whole project.

    `contents` maps a normalised path to the file's text.
    """
    files: list[FileSkeleton] = []

    for path, content in contents.items():
        language = _language_of(path)
        if language == "python":
            files.append(parse_python(path, content))
        elif language == "javascript":
            files.append(parse_javascript(path, content))

    known_paths = {file.path for file in files}
    python_modules = python_module_map(files)

    imports_graph: dict[str, list[str]] = {}
    imported_by: dict[str, list[str]] = {file.path: [] for file in files}
    external: set[str] = set()

    for file in files:
        internal: list[str] = []
        for raw in file.imports:
            if file.language == "python":
                target = _resolve_python(raw, file.path, python_modules)
            else:
                target = _resolve_javascript(raw, file.path, known_paths)

            if target and target != file.path:
                if target not in internal:
                    internal.append(target)
                    imported_by[target].append(file.path)
            elif target is None:
                package = raw.lstrip(".").split(".")[0].split("/")[0]
                # sys.stdlib_module_names lets us tell "part of Python" from
                # "an installed dependency" without a network call.
                if package and package not in sys.stdlib_module_names:
                    external.add(package)

        imports_graph[file.path] = internal

    entry_points = [file.path for file in files if file.is_entry_point]

    return ProjectSkeleton(
        files=files,
        entry_points=sorted(entry_points),
        imports_graph=imports_graph,
        imported_by=imported_by,
        external_dependencies=sorted(external),
    )


def reading_order(skeleton: ProjectSkeleton, limit: int = 5) -> list[str]:
    """Suggest which files to read first, and in what order.

    Computed, not guessed: the most-imported file is where the shared
    concepts live, so it comes first; entry points come next because they
    show how the parts are assembled.

    This is the deterministic half of "where to start reading". The LLM
    explains an order we can defend, instead of inventing one we cannot.
    """
    def score(file: FileSkeleton) -> tuple[int, int, int]:
        return (
            # Most-imported first: that is where shared concepts live.
            -len(skeleton.imported_by.get(file.path, [])),
            # A file that declares nothing teaches nothing. An empty
            # __init__.py can look like a hub while being worth no reading
            # time at all.
            0 if file.symbols else 1,
            # Entry points next: they show how the parts fit together.
            0 if file.is_entry_point else 1,
        )

    ranked = sorted(skeleton.files, key=score)
    return [file.path for file in ranked[:limit]]
