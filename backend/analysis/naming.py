"""Layer 3b: names and small readability traps.

This module produces the CANDIDATES for the report's flagship section,
"Symbols to clarify".

The split matters:

  * These rules answer "which names deserve a second look?" — cheaply, and
    without ever being wrong about *where* to look.
  * The LLM answers the only question that needs intelligence: "what does
    this variable actually hold, and what should it be called?"

A linter can say `x` is a bad name. It cannot say `x` holds a token expiry
date. So we flag generously here and let the model filter: a false candidate
costs a few tokens, a missed one costs the reader an hour.

Everything is read from the syntax tree, so a name written in a string or a
comment is never flagged.
"""

import ast
from typing import NamedTuple

# Loop counters and idiomatic short names that read fine in context.
TOLERATED_SHORT_NAMES = {"i", "j", "k", "n", "x", "y", "z", "_", "id", "ok", "db"}

# Names that describe nothing: they say a value exists, not what it is.
#
# Deliberately conservative. Words like `content`, `response`, `items` and
# `payload` were removed after running this detector on the project itself:
# they are frequently the RIGHT name (a field literally holding the file
# content), and flagging them buried the real findings in noise.
PLACEHOLDER_NAMES = {
    "data",
    "temp",
    "tmp",
    "val",
    "value",
    "result",
    "res",
    "obj",
    "thing",
    "things",
    "info",
    "stuff",
    "foo",
    "bar",
    "baz",
    "arr",
    "lst",
    "dct",
    "var",
}

# Numbers that carry no hidden meaning.
HARMLESS_NUMBERS = {0, 1, -1, 2, 100}

MIN_NAME_LENGTH = 3


class NameFinding(NamedTuple):
    """A candidate for clarification, in the shape every detector produces."""

    line: int
    severity: str
    message: str
    suggestion: str
    category: str
    penalty: int
    symbol: str | None = None
    source: str = "naming"


def _is_numbered_name(name: str) -> bool:
    """True for names like str1, df3, list2: a counter, not a description."""
    return len(name) > 1 and name[-1].isdigit() and not name.rstrip("0123456789").isupper()


def _assigned_names(tree: ast.AST):
    """Yield every (name, line) assigned anywhere in the tree.

    A bare annotation with no value (`path: str` in a NamedTuple) is a field
    DECLARATION, not an assignment, and is skipped.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    yield target.id, target.lineno
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                yield node.target.id, node.target.lineno
        elif isinstance(node, (ast.For, ast.AsyncFor)) and isinstance(node.target, ast.Name):
            yield node.target.id, node.target.lineno


def _read_names(tree: ast.AST) -> set[str]:
    """Every name the file READS, as opposed to writes."""
    return {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }


def _check_name(name: str, line: int) -> NameFinding | None:
    """Decide whether one name deserves a second look."""
    if name in TOLERATED_SHORT_NAMES or name.startswith("__"):
        return None

    lowered = name.lower()

    if lowered in PLACEHOLDER_NAMES:
        return NameFinding(
            line=line,
            severity="low",
            message=f"'{name}' describes nothing: it says a value exists, "
            "not what it is.",
            suggestion="Rename it after what it holds, not after its type.",
            category="readability",
            penalty=2,
            symbol=name,
        )

    if len(name) < MIN_NAME_LENGTH:
        return NameFinding(
            line=line,
            severity="low",
            message=f"'{name}' is too short to say what it holds.",
            suggestion="A reader should not have to trace the code to learn "
            "what this contains.",
            category="readability",
            penalty=2,
            symbol=name,
        )

    if _is_numbered_name(name):
        return NameFinding(
            line=line,
            severity="low",
            message=f"'{name}' is numbered rather than named.",
            suggestion="Numbering hides the difference between the two values. "
            "Name each after its role.",
            category="readability",
            penalty=2,
            symbol=name,
        )

    return None


def find_weak_names(content: str) -> list[NameFinding]:
    """Names that a newcomer would have to decode."""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return []

    findings: list[NameFinding] = []
    already: set[str] = set()

    for name, line in _assigned_names(tree):
        if name in already:
            continue
        finding = _check_name(name, line)
        if finding is not None:
            already.add(name)
            findings.append(finding)

    return findings


def find_magic_numbers(content: str) -> list[NameFinding]:
    """Unexplained numeric literals.

    `if age > 17` reads as arbitrary: nobody ever says *why* 17. A named
    constant turns the number into documentation.
    """
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return []

    findings: list[NameFinding] = []
    # A number assigned to an UPPER_CASE constant is already explained.
    explained_lines = {
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id.isupper() for t in node.targets)
    }

    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant):
            continue
        if not isinstance(node.value, (int, float)) or isinstance(node.value, bool):
            continue
        if node.value in HARMLESS_NUMBERS or node.lineno in explained_lines:
            continue

        findings.append(
            NameFinding(
                line=node.lineno,
                severity="low",
                message=f"The number {node.value} appears with no explanation.",
                suggestion="Give it a named constant so the reader learns why "
                "this value and not another.",
                category="readability",
                penalty=1,
                symbol=str(node.value),
            )
        )

    return findings


def find_boolean_parameters(content: str) -> list[NameFinding]:
    """Boolean parameters make the CALL SITE unreadable.

    `create(True, False)` tells the reader nothing; they have to open the
    function to find out what the two flags mean.
    """
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return []

    findings: list[NameFinding] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        defaults = node.args.defaults
        positional = node.args.args[len(node.args.args) - len(defaults):]
        for argument, default in zip(positional, defaults):
            if isinstance(default, ast.Constant) and isinstance(default.value, bool):
                findings.append(
                    NameFinding(
                        line=node.lineno,
                        severity="low",
                        message=f"'{node.name}' takes a boolean parameter "
                        f"'{argument.arg}'.",
                        suggestion="At the call site a bare True or False says "
                        "nothing. Consider two functions, or an explicit enum.",
                        category="best_practices",
                        penalty=2,
                        symbol=f"{node.name}.{argument.arg}",
                    )
                )

    return findings


def find_unused_variables(content: str) -> list[NameFinding]:
    """Variables assigned inside a function and never read there.

    Often the residue of a half-finished change — which makes them a real
    signal, not just tidiness.

    **Only function-local variables count.** A module-level constant or a
    class attribute is part of the file's public surface: another file may
    import it, and this module only ever sees one file at a time. Reporting
    those produced a flood of false positives when this detector was first
    run against the project itself.
    """
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return []

    findings: list[NameFinding] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        read = _read_names(node)
        already: set[str] = set()

        for name, line in _assigned_names(node):
            if name in read or name in already or name.startswith("_"):
                continue
            already.add(name)
            findings.append(
                NameFinding(
                    line=line,
                    severity="low",
                    message=f"'{name}' is assigned but never used.",
                    suggestion="Remove it, or finish what it was meant for: "
                    "an unused variable often marks an unfinished change.",
                    category="best_practices",
                    penalty=2,
                    symbol=name,
                )
            )

    return findings


def analyse(path: str, content: str) -> list[NameFinding]:
    """Every naming candidate for one file."""
    if not path.endswith(".py"):
        # JS/TS needs a real parser to do this without false positives.
        # Guessing from text is exactly the mistake this project avoids.
        return []

    findings = [
        *find_weak_names(content),
        *find_magic_numbers(content),
        *find_boolean_parameters(content),
        *find_unused_variables(content),
    ]
    return sorted(findings, key=lambda finding: finding.line)
