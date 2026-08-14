"""The rule-based analysis engine.

No LLM here. This module applies simple rules to the code it receives and
produces a full report: detected language, findings with real line numbers,
and a score per category.

Scoring principle: every category starts at 20/20 and LOSES points for each
problem found. Perfect code therefore scores 100/100.

This is the SEAM. When Semgrep and Claude take over, only the inside of
`build_analysis` changes: its signature and the shape of its result stay the
same, so no other file in the project needs to change.
"""

import re
from datetime import datetime, timezone
from uuid import uuid4

CATEGORIES = (
    "security",
    "readability",
    "maintainability",
    "performance",
    "best_practices",
)

MAX_SCORE = 20
MAX_LINE_LENGTH = 100
MAX_FUNCTION_LINES = 40
MAX_ISSUES = 20
DEFAULT_LANGUAGE = "unknown"


# --------------------------------------------------------------------------
# Language detection: we count telltale markers for each language.
# --------------------------------------------------------------------------

LANGUAGE_MARKERS = {
    "python": ("def ", "import ", "elif ", "print(", "self."),
    "javascript": ("function ", "const ", "let ", "=>", "console.log"),
    "java": ("public class", "System.out", "private ", "void "),
    "sql": ("select ", "insert into", "create table"),
    "php": ("<?php", "echo ", "$this->"),
}


def detect_language(code: str) -> str:
    """Guess the language by counting markers found in the code."""
    lowered = code.lower()
    best = DEFAULT_LANGUAGE
    best_score = 0

    for language, markers in LANGUAGE_MARKERS.items():
        score = sum(lowered.count(marker) for marker in markers)
        if score > best_score:
            best, best_score = language, score

    return best


# --------------------------------------------------------------------------
# Tests, one small function per rule. Each answers yes/no for ONE line.
# --------------------------------------------------------------------------

SQL_KEYWORDS = ("select ", "insert ", "update ", "delete ", "where ")
CONCATENATION = ("+", ".format(", "%s", 'f"', "f'", "${")


def _sql_concatenation(line: str) -> bool:
    lowered = line.lower()
    has_sql = any(keyword in lowered for keyword in SQL_KEYWORDS)
    return has_sql and any(sign in line for sign in CONCATENATION)


def _dangerous_call(line: str) -> bool:
    return "eval(" in line or "exec(" in line


SECRET_WORDS = ("password", "passwd", "secret", "api_key", "apikey", "token")


def _hardcoded_secret(line: str) -> bool:
    if "=" not in line:
        return False
    left, right = line.split("=", 1)
    if not any(word in left.lower() for word in SECRET_WORDS):
        return False
    # A secret written in the clear is quoted in the source.
    return '"' in right or "'" in right


def _line_too_long(line: str) -> bool:
    return len(line) > MAX_LINE_LENGTH


# re = regular expressions. This pattern matches an assignment whose variable
# name is a single letter: "x = ...", "let a = ...".
SHORT_NAME_PATTERN = re.compile(r"^\s*(?:let |const |var )?([A-Za-z])\s*=[^=]")
TOLERATED_LETTERS = {"i", "j", "k", "n"}


def _name_too_short(line: str) -> bool:
    found = SHORT_NAME_PATTERN.match(line)
    return found is not None and found.group(1) not in TOLERATED_LETTERS


def _bare_except(line: str) -> bool:
    cleaned = line.strip()
    return cleaned in ("except:", "catch {", "} catch {")


def _debug_trace(line: str) -> bool:
    return "console.log(" in line or line.strip().startswith("print(")


# --------------------------------------------------------------------------
# The catalogue of rules applied line by line.
# Adding a rule = adding a dictionary here, nothing else to change.
# --------------------------------------------------------------------------

LINE_RULES = [
    {
        "test": _sql_concatenation,
        "category": "security",
        "severity": "critical",
        "penalty": 8,
        "message": "SQL query assembled by concatenation: SQL injection is possible.",
        "suggestion": "Use a parameterised query instead of assembling the string.",
    },
    {
        "test": _dangerous_call,
        "category": "security",
        "severity": "critical",
        "penalty": 8,
        "message": "Call to eval()/exec(): arbitrary code execution is possible.",
        "suggestion": "Replace with an explicit conversion or a list of allowed values.",
    },
    {
        "test": _hardcoded_secret,
        "category": "security",
        "severity": "high",
        "penalty": 6,
        "message": "Secret hardcoded in the source.",
        "suggestion": "Move the value into an environment variable (.env).",
    },
    {
        "test": _line_too_long,
        "category": "readability",
        "severity": "low",
        "penalty": 2,
        "message": f"Line longer than {MAX_LINE_LENGTH} characters.",
        "suggestion": "Break the line so it stays readable without scrolling.",
    },
    {
        "test": _name_too_short,
        "category": "readability",
        "severity": "low",
        "penalty": 2,
        "message": "Single-letter variable name.",
        "suggestion": "Choose a name that describes what the variable holds.",
    },
    {
        "test": _bare_except,
        "category": "best_practices",
        "severity": "medium",
        "penalty": 4,
        "message": "All errors caught without distinction.",
        "suggestion": "Catch the expected error type so real bugs are not hidden.",
    },
    {
        "test": _debug_trace,
        "category": "best_practices",
        "severity": "low",
        "penalty": 2,
        "message": "Debug trace left in the code.",
        "suggestion": "Use a logger: configurable and switchable off in production.",
    },
]


# --------------------------------------------------------------------------
# Structural rules: they look at several lines at once, so they do not fit
# the catalogue above.
# --------------------------------------------------------------------------


def _indentation(line: str) -> int:
    return len(line) - len(line.lstrip())


def _is_loop(line: str) -> bool:
    cleaned = line.strip()
    return cleaned.startswith(("for ", "for(", "while ", "while("))


def _is_definition(line: str) -> bool:
    cleaned = line.strip()
    return cleaned.startswith(("def ", "function "))


def nested_loops(lines: list[str]) -> list[int]:
    """Line numbers where a loop opens inside another loop.

    We push the indentation of each open loop onto a stack. When indentation
    returns to the same level or lower, that loop is closed: we pop.
    """
    numbers = []
    open_loops = []

    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        indent = _indentation(line)
        while open_loops and indent <= open_loops[-1]:
            open_loops.pop()

        if _is_loop(line):
            if open_loops:
                numbers.append(number)
            open_loops.append(indent)

    return numbers


def long_functions(lines: list[str]) -> list[tuple[int, int]]:
    """Pairs of (definition line, line count) for functions that are too long."""
    results = []

    for index, line in enumerate(lines):
        if not _is_definition(line):
            continue

        def_indent = _indentation(line)
        size = 0
        # A function body is everything indented more deeply than the def.
        for following in lines[index + 1 :]:
            if following.strip() and _indentation(following) <= def_indent:
                break
            size += 1

        if size > MAX_FUNCTION_LINES:
            results.append((index + 1, size))

    return results


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------


def _find_issues(code: str) -> list[dict]:
    """Apply every rule and return the list of problems found."""
    lines = code.splitlines()
    issues = []

    for number, line in enumerate(lines, start=1):
        for rule in LINE_RULES:
            if rule["test"](line):
                issues.append(
                    {
                        "line": number,
                        "severity": rule["severity"],
                        "message": rule["message"],
                        "suggestion": rule["suggestion"],
                        "category": rule["category"],
                        "penalty": rule["penalty"],
                    }
                )

    for number in nested_loops(lines):
        issues.append(
            {
                "line": number,
                "severity": "medium",
                "message": "Loop nested inside another loop.",
                "suggestion": "Check the cost: the number of operations grows very fast.",
                "category": "performance",
                "penalty": 5,
            }
        )

    for number, size in long_functions(lines):
        issues.append(
            {
                "line": number,
                "severity": "medium",
                "message": f"Function of {size} lines: several responsibilities mixed together.",
                "suggestion": "Split into short functions, one responsibility each.",
                "category": "maintainability",
                "penalty": 5,
            }
        )

    issues.sort(key=lambda issue: issue["line"])
    return issues[:MAX_ISSUES]


def _compute_scores(issues: list[dict]) -> dict:
    """Each category starts at 20 and loses points, never dropping below 0."""
    scores = {category: MAX_SCORE for category in CATEGORIES}

    for issue in issues:
        category = issue["category"]
        scores[category] = max(0, scores[category] - issue["penalty"])

    return scores


def build_analysis(code: str, language: str | None = None) -> dict:
    """Build an analysis report from the code actually submitted."""
    issues = _find_issues(code)
    scores = _compute_scores(issues)

    # Only the four fields declared by the Issue schema are kept: category
    # and penalty are internal to the engine.
    public_issues = [
        {
            "line": issue["line"],
            "severity": issue["severity"],
            "message": issue["message"],
            "suggestion": issue["suggestion"],
        }
        for issue in issues
    ]

    return {
        "id": str(uuid4()),
        "language": language or detect_language(code),
        "scores": scores,
        "total_score": sum(scores.values()),
        "issues": public_issues,
        "created_at": datetime.now(timezone.utc),
    }
