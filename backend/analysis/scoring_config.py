"""Every scoring threshold, in one place.

No magic numbers anywhere else in the codebase. Each value below carries a
one-line comment saying what it means, so the whole scoring policy can be
read, argued with and changed here without touching any logic.

Two scoring methods, borrowed from SonarQube, because different qualities
behave differently:

  * **Security** is scored by the WORST finding. One SQL injection is
    critical in a 30-line file and in a 5000-line one — size has nothing to
    do with exploitability.
  * **Everything else** is scored by DENSITY. Three long lines in 30 is
    sloppy; the same three in 500 is noise.
"""

# --------------------------------------------------------------------------
# Security: the worst finding sets a ceiling on the score
# --------------------------------------------------------------------------

# Worst severity present -> the highest security score still achievable.
SEVERITY_TO_SECURITY_SCORE = {
    "critical": 5,  # e.g. SQL injection, eval of user input: exploitable today
    "high": 10,  # e.g. hardcoded secret, weak hash: serious, not always reachable
    "medium": 14,  # a real weakness, needing other conditions to be exploited
    "low": 17,  # worth fixing, hard to abuse on its own
}

# No security finding at all.
SECURITY_SCORE_WHEN_CLEAN = 20

# --------------------------------------------------------------------------
# Density: how much each finding weighs
# --------------------------------------------------------------------------

# Penalty points contributed by one finding, by severity.
SEVERITY_WEIGHT = {
    "critical": 10,  # ten times a low finding: severity must dominate volume
    "high": 6,
    "medium": 3,
    "low": 1,
}

# Weight given to a severity we do not recognise (defensive; should not happen).
DEFAULT_SEVERITY_WEIGHT = 3

# --------------------------------------------------------------------------
# Density curve: weighted findings per 100 lines -> score out of 20
# --------------------------------------------------------------------------

# Read as "density <= threshold gives this score". First match wins, so the
# list must stay sorted by threshold.
DENSITY_TO_SCORE = (
    (0.0, 20),  # nothing found
    (1.0, 18),  # about one low-severity finding per 100 lines
    (2.0, 16),
    (4.0, 13),
    (7.0, 10),  # roughly one medium finding every 40 lines
    (12.0, 6),
)

# Density above the last threshold.
DENSITY_FLOOR_SCORE = 3

# --------------------------------------------------------------------------
# Grades: project total out of 100 -> letter
# --------------------------------------------------------------------------

# Read as "total >= threshold gives this grade". Sorted highest first.
GRADE_THRESHOLDS = (
    (85, "A"),  # healthy: nothing serious, low noise
    (70, "B"),  # sound, with visible rough edges
    (55, "C"),  # works, but carries real debt
    (40, "D"),  # needs attention before building on it
)

# Below the last threshold.
GRADE_FLOOR = "E"

# Best-to-worst, used to compare two grades.
GRADE_ORDER = ("A", "B", "C", "D", "E")

# A ceiling on the grade, imposed by the security score whatever the total.
#
# Why this exists: a file whose ONLY flaw is a SQL injection scores
# 5 + 20 + 20 + 20 + 20 = 85, which is exactly the A threshold. The sample
# bad_security.py — SQL injection, hardcoded token, command injection, MD5
# and eval — graded A before this was added. A tool that awards top marks to
# exploitable code teaches the wrong lesson and discredits every other score
# it produces.
#
# Read as "a security score at or below this key caps the grade at this
# value". Set to an empty dict to disable and score purely on the total.
SECURITY_GRADE_CEILING = {
    5: "D",  # a critical finding: never better than D, however tidy the rest
    10: "C",  # a high-severity finding
    14: "B",  # a medium finding
}

# --------------------------------------------------------------------------
# Shape of the score
# --------------------------------------------------------------------------

MAX_CATEGORY_SCORE = 20  # each category is out of 20
MIN_CATEGORY_SCORE = 0  # a score can never go negative
LINES_PER_DENSITY_UNIT = 100  # density is expressed per 100 lines

# A file of 0 lines must not divide by zero. Using 1 keeps the arithmetic
# defined; an empty file has no findings anyway, so it scores full marks.
MIN_LINES_FOR_DENSITY = 1

# --------------------------------------------------------------------------
# Coverage: which detector feeds which category
# --------------------------------------------------------------------------

# A score of 20 must never be confused with "we looked and found nothing".
# If no detector for a category could run on a file, the category is reported
# as not evaluated, whatever the score says.
CATEGORY_DETECTORS = {
    "security": ("semgrep",),
    "readability": ("metrics_text", "naming"),
    "maintainability": ("metrics_text", "metrics_python", "clones"),
    # Semgrep joined this category when the performance rule pack was
    # written; before that a score of 20 here mostly meant "one detector
    # looked", which the coverage flag was carrying alone.
    "performance": ("semgrep", "metrics_python"),
    "best_practices": ("semgrep", "naming"),
}

CATEGORIES = tuple(CATEGORY_DETECTORS)

# Coverage labels used in the response.
COVERAGE_FULL = "evaluated"
COVERAGE_PARTIAL = "partially_evaluated"
COVERAGE_NONE = "not_evaluated"

# File extensions each detector understands.
PYTHON_ONLY_DETECTORS = ("metrics_python", "naming", "clones")
SEMGREP_EXTENSIONS = (".py", ".js", ".jsx", ".ts", ".tsx")
