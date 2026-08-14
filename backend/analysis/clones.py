"""Layer 3c: duplicated functions.

Copy-paste is how a small bug becomes three bugs: someone fixes one copy and
the others keep going. Finding duplicates needs no LLM at all — only hashing.

Two levels, matching the standard clone-detection vocabulary:

  * **Type 1, exact** — identical once comments and whitespace are removed.
    Works in any language.
  * **Type 2, structural** — identical shape, different names. Detected by
    walking the Python syntax tree and replacing every identifier with a
    placeholder, so `validate_email` and `check_mail` collapse to one hash.

The LLM then adds the judgement a hash cannot: are these genuinely the same
logic, or do they merely look alike?
"""

import ast
import hashlib
import re
from typing import NamedTuple

# Below this many statements, functions are too trivial to compare: every
# two-line getter in the project would collide.
MIN_STATEMENTS = 3

COMMENT_PATTERN = re.compile(r"#.*$", re.M)


class ClonePair(NamedTuple):
    """Two functions that appear to be duplicates."""

    kind: str  # "exact" | "structural"
    first_path: str
    first_name: str
    first_line: int
    second_path: str
    second_name: str
    second_line: int


class CloneFinding(NamedTuple):
    """A duplicate reported in the shape every detector produces."""

    line: int
    severity: str
    message: str
    suggestion: str
    category: str
    penalty: int
    path: str
    source: str = "clones"


class _Function(NamedTuple):
    path: str
    name: str
    line: int
    exact_hash: str
    shape_hash: str | None


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalise_text(source: str) -> str:
    """Strip comments, blank lines and indentation.

    What remains is the logic itself, so two copies that differ only in
    formatting produce the same hash.
    """
    without_comments = COMMENT_PATTERN.sub("", source)
    lines = [line.strip() for line in without_comments.splitlines()]
    return "\n".join(line for line in lines if line)


def _shape(node: ast.AST) -> str:
    """A structural signature: node types only, no names, no values.

    Two functions differing only in their variable and function names produce
    exactly the same signature — that is the whole point.
    """
    children = ",".join(_shape(child) for child in ast.iter_child_nodes(node))
    return f"{type(node).__name__}({children})"


def _statement_count(node) -> int:
    return sum(1 for child in ast.walk(node) if isinstance(child, ast.stmt))


def _python_functions(path: str, content: str) -> list[_Function]:
    """Every top-level and nested function of a Python file, hashed twice."""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return []

    lines = content.splitlines()
    functions: list[_Function] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if _statement_count(node) < MIN_STATEMENTS:
            continue

        end = getattr(node, "end_lineno", node.lineno)
        source = "\n".join(lines[node.lineno - 1 : end])

        # The body only: two functions with the same body but different
        # names are still duplicates.
        body_shape = ",".join(_shape(statement) for statement in node.body)

        functions.append(
            _Function(
                path=path,
                name=node.name,
                line=node.lineno,
                exact_hash=_hash(_normalise_text(source)),
                shape_hash=_hash(body_shape),
            )
        )

    return functions


def find_pairs(contents: dict[str, str]) -> list[ClonePair]:
    """Find duplicated functions across a whole project."""
    functions: list[_Function] = []
    for path, content in contents.items():
        if path.endswith(".py"):
            functions.extend(_python_functions(path, content))

    pairs: list[ClonePair] = []
    reported: set[tuple[str, str]] = set()

    def key(function: _Function) -> str:
        return f"{function.path}:{function.name}"

    # Exact duplicates first, so a pair is never reported twice.
    for group_hash, kind in (("exact_hash", "exact"), ("shape_hash", "structural")):
        buckets: dict[str, list[_Function]] = {}
        for function in functions:
            value = getattr(function, group_hash)
            if value is None:
                continue
            buckets.setdefault(value, []).append(function)

        for bucket in buckets.values():
            if len(bucket) < 2:
                continue
            for index, first in enumerate(bucket):
                for second in bucket[index + 1 :]:
                    identity = tuple(sorted((key(first), key(second))))
                    if identity in reported:
                        continue
                    reported.add(identity)
                    pairs.append(
                        ClonePair(
                            kind=kind,
                            first_path=first.path,
                            first_name=first.name,
                            first_line=first.line,
                            second_path=second.path,
                            second_name=second.name,
                            second_line=second.line,
                        )
                    )

    return pairs


def analyse(contents: dict[str, str]) -> list[CloneFinding]:
    """Duplicated functions, as findings attached to the second copy."""
    findings: list[CloneFinding] = []

    for pair in find_pairs(contents):
        if pair.kind == "exact":
            what = "is identical to"
            penalty = 5
        else:
            what = "has the same structure as"
            penalty = 3

        where = (
            f"{pair.first_name}() in {pair.first_path} line {pair.first_line}"
            if pair.first_path != pair.second_path
            else f"{pair.first_name}() on line {pair.first_line}"
        )

        findings.append(
            CloneFinding(
                line=pair.second_line,
                severity="medium",
                message=f"'{pair.second_name}()' {what} {where}.",
                suggestion="Keep one and call it from both places: "
                "otherwise a fix applied to one copy leaves the other broken.",
                category="maintainability",
                penalty=penalty,
                path=pair.second_path,
            )
        )

    return findings
