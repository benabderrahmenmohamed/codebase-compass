"""Layer 3a: measurements.

Semgrep is a pattern matcher: excellent at "this shape of code is dangerous",
the wrong tool for "this function is 80 lines long". Those are measurements,
and measurements are what this module produces.

It covers the three categories Semgrep cannot reach: readability,
maintainability and performance.

Python is measured on its syntax tree, so a `def` written inside a string or
a comment is never counted. Line length is textual by nature and applies to
every language.
"""

import ast
from typing import NamedTuple

MAX_LINE_LENGTH = 100
MAX_FUNCTION_LINES = 40
MAX_NESTING_DEPTH = 3
MAX_FILE_LINES = 500

# Nodes that add a level of nesting when you read code.
NESTING_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)

LOOP_NODES = (ast.For, ast.AsyncFor, ast.While)


class Measurement(NamedTuple):
    """One measured problem, in the shape every detector produces."""

    line: int
    severity: str
    message: str
    suggestion: str
    category: str
    penalty: int
    source: str = "metrics"


def _function_length(node) -> int:
    """Number of lines a function spans, from its `def` to its last line."""
    end = getattr(node, "end_lineno", None)
    if end is None:  # pragma: no cover - every supported Python sets it
        return 0
    return end - node.lineno + 1


def _max_depth(node, depth: int = 0) -> int:
    """Deepest nesting level inside a function body."""
    deepest = depth
    for child in ast.iter_child_nodes(node):
        child_depth = depth + 1 if isinstance(child, NESTING_NODES) else depth
        deepest = max(deepest, _max_depth(child, child_depth))
    return deepest


def _nested_loops(tree: ast.AST) -> list[int]:
    """Lines where a loop sits inside another loop.

    Nested loops multiply work: two loops over 1000 items is a million
    operations. It is the most common reason a page suddenly gets slow.
    """
    lines = []
    for node in ast.walk(tree):
        if not isinstance(node, LOOP_NODES):
            continue
        for child in ast.walk(node):
            if child is not node and isinstance(child, LOOP_NODES):
                lines.append(child.lineno)
    return sorted(set(lines))


def measure_text(content: str) -> list[Measurement]:
    """Measurements that work on any language, from the text alone."""
    findings: list[Measurement] = []
    lines = content.splitlines()

    for number, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            findings.append(
                Measurement(
                    line=number,
                    severity="low",
                    message=f"Line of {len(line)} characters "
                    f"(over {MAX_LINE_LENGTH}).",
                    suggestion="Break the line so it reads without scrolling sideways.",
                    category="readability",
                    penalty=1,
                )
            )

    if len(lines) > MAX_FILE_LINES:
        findings.append(
            Measurement(
                line=1,
                severity="medium",
                message=f"File of {len(lines)} lines "
                f"(over {MAX_FILE_LINES}).",
                suggestion="Split it: a file this long usually holds several concerns.",
                category="maintainability",
                penalty=4,
            )
        )

    return findings


def measure_python(content: str) -> list[Measurement]:
    """Structural measurements that need the syntax tree."""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        # A file that does not parse is not a failure here: the textual
        # measurements still applied, and one broken file must not stop the
        # analysis of the rest.
        return []

    findings: list[Measurement] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            length = _function_length(node)
            if length > MAX_FUNCTION_LINES:
                findings.append(
                    Measurement(
                        line=node.lineno,
                        severity="medium",
                        message=f"Function '{node.name}' is {length} lines long "
                        f"(over {MAX_FUNCTION_LINES}).",
                        suggestion="Split it into short functions, "
                        "one responsibility each.",
                        category="maintainability",
                        penalty=5,
                    )
                )

            depth = _max_depth(node)
            if depth > MAX_NESTING_DEPTH:
                findings.append(
                    Measurement(
                        line=node.lineno,
                        severity="medium",
                        message=f"Function '{node.name}' nests {depth} levels deep "
                        f"(over {MAX_NESTING_DEPTH}).",
                        suggestion="Return early instead of wrapping the body in "
                        "another condition.",
                        category="maintainability",
                        penalty=4,
                    )
                )

    for line in _nested_loops(tree):
        findings.append(
            Measurement(
                line=line,
                severity="medium",
                message="Loop nested inside another loop.",
                suggestion="Check the cost: the number of operations grows very fast.",
                category="performance",
                penalty=5,
            )
        )

    return findings


def measure(path: str, content: str) -> list[Measurement]:
    """All measurements for one file."""
    findings = measure_text(content)
    if path.endswith(".py"):
        findings.extend(measure_python(content))
    return sorted(findings, key=lambda finding: finding.line)
