"""Analysing a single snippet, through the same pipeline as a project.

This replaces `rule_engine.py`, which was a second, parallel implementation
of the whole analysis: its own regular-expression rules and its own scoring
model, in which every category started at 20 and lost a fixed penalty per
finding.

Having two engines meant having two answers. The same SQL injection scored
5 out of 20 for security through the project pipeline — the worst finding
drives the score — and 12 out of 20 here, because three separate
subtractions happened to land differently. A tool that grades the same
defect two ways cannot defend either number.

It also meant the snippet path never received the improvements made
everywhere else. It matched SQL by looking for keywords and a plus sign on
one line, which is precisely the rule that was rewritten in taint mode after
it flagged a documentation example as the project's most critical finding.
The snippet path kept that bug for as long as it existed.

**The one thing worth keeping was language detection.** The pipeline decides
what to run from the file PATH — a `.py` file gets the Python detectors —
and a snippet has no path. So the language is guessed from the code, mapped
to a synthetic filename, and the ordinary pipeline runs on a one-file
project. Everything downstream is the code that analyses real projects.
"""

from datetime import datetime, timezone
from uuid import uuid4

from analysis import report

DEFAULT_LANGUAGE = "unknown"

# Telltale markers, counted. Crude, and adequate: the answer only has to
# pick the right DETECTORS, and a wrong guess degrades to the language-
# agnostic ones rather than producing something false.
LANGUAGE_MARKERS = {
    "python": ("def ", "import ", "elif ", "print(", "self.", "None", "True"),
    "javascript": ("function ", "const ", "let ", "=>", "console.log", "==="),
    "java": ("public class", "System.out", "private ", "void ", "String["),
    "php": ("<?php", "echo ", "$this->", "->"),
}

# The filename each language is analysed under. The extension is the whole
# point: it is what tells the pipeline which detectors apply.
FILENAME_FOR = {
    "python": "snippet.py",
    "javascript": "snippet.js",
    "java": "snippet.java",
    "php": "snippet.php",
    DEFAULT_LANGUAGE: "snippet.txt",
}


def detect_language(code: str) -> str:
    """Guess the language by counting markers found in the code."""
    lowered = code.lower()
    best, best_score = DEFAULT_LANGUAGE, 0

    for language, markers in LANGUAGE_MARKERS.items():
        score = sum(lowered.count(marker.lower()) for marker in markers)
        if score > best_score:
            best, best_score = language, score

    return best


def filename_for(language: str) -> str:
    """The synthetic path a snippet is analysed under."""
    return FILENAME_FOR.get(language, FILENAME_FOR[DEFAULT_LANGUAGE])


def analyse(code: str, language: str | None = None) -> dict:
    """Analyse one snippet and return a report in the snippet shape.

    The response contract is unchanged — five integer scores and a flat
    list of issues — so every existing client keeps working. What changed
    is where the numbers come from.
    """
    detected = language or detect_language(code)
    path = filename_for(detected)

    # use_llm is False: the snippet contract has no field for written
    # explanations, so asking for them would spend money on output that is
    # then discarded.
    full = report.analyse_project({path: code}, use_llm=False)

    return {
        "id": str(uuid4()),
        "language": detected,
        "scores": {name: category["score"] for name, category in full["scores"].items()},
        "total_score": full["total_score"],
        "issues": [
            {
                "line": finding["line"],
                "severity": finding["severity"],
                "message": finding["message"],
                "suggestion": finding["suggestion"],
            }
            for finding in full["findings"]
        ],
        "created_at": datetime.now(timezone.utc),
    }
