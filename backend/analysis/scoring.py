"""Layer 4: turning findings into scores.

Two methods, one per kind of quality — see scoring_config.py for every
threshold and the reasoning behind it.

The project score is **not** the average of the file scores. Averaging would
let a 500-line clean file and a 30-line disaster cancel out, and would let a
critical injection be diluted by good neighbours. Instead:

  * security  -> worst finding across the WHOLE project
  * the rest  -> density over the whole project (total weight / total lines)

That is the same reasoning applied at a different scale, not a different
policy.
"""

from typing import NamedTuple

from analysis import scoring_config as config
from analysis.findings import Finding

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class CategoryScore(NamedTuple):
    """One category's score, with enough context to defend it."""

    score: int
    coverage: str  # evaluated | partially_evaluated | not_evaluated
    finding_count: int
    weight: int  # summed penalty weights, before the curve
    method: str  # "worst_finding" | "density"
    density: float | None = None  # weighted findings per 100 lines


class FileScore(NamedTuple):
    path: str
    lines: int
    scores: dict[str, CategoryScore]
    total: int
    grade: str
    top_finding: Finding | None


class ProjectScore(NamedTuple):
    scores: dict[str, CategoryScore]
    total: int
    grade: str | None
    files: list[FileScore]
    worst_file: str | None
    best_file: str | None
    is_empty: bool = False


# --------------------------------------------------------------------------
# The two methods
# --------------------------------------------------------------------------


def worst_severity(findings) -> str | None:
    """The most serious severity present, or None."""
    if not findings:
        return None
    return min((f.severity for f in findings), key=lambda s: SEVERITY_RANK.get(s, 9))


def security_score(findings) -> int:
    """Score set by the WORST finding, never by how many there are.

    Ten low-severity issues are not worse than one SQL injection, and a score
    that says otherwise teaches the wrong lesson.
    """
    worst = worst_severity(findings)
    if worst is None:
        return config.SECURITY_SCORE_WHEN_CLEAN
    return config.SEVERITY_TO_SECURITY_SCORE.get(
        worst, config.SECURITY_SCORE_WHEN_CLEAN
    )


def total_weight(findings) -> int:
    """Sum of the penalty weights of a set of findings."""
    return sum(
        config.SEVERITY_WEIGHT.get(f.severity, config.DEFAULT_SEVERITY_WEIGHT)
        for f in findings
    )


def density_of(weight: int, lines: int) -> float:
    """Weighted findings per 100 lines."""
    safe_lines = max(lines, config.MIN_LINES_FOR_DENSITY)
    return weight * config.LINES_PER_DENSITY_UNIT / safe_lines


def density_score(density: float) -> int:
    """Map a density onto a score out of 20 using the configured curve."""
    for threshold, score in config.DENSITY_TO_SCORE:
        if density <= threshold:
            return score
    return config.DENSITY_FLOOR_SCORE


def grade_for(total: float) -> str:
    """Letter grade for a total out of 100, before any ceiling."""
    for threshold, letter in config.GRADE_THRESHOLDS:
        if total >= threshold:
            return letter
    return config.GRADE_FLOOR


def worse_grade(first: str, second: str) -> str:
    """The lower of two grades."""
    order = config.GRADE_ORDER
    return first if order.index(first) >= order.index(second) else second


def apply_security_ceiling(grade: str, security: int) -> str:
    """Cap a grade according to how bad the security score is.

    Without this, code whose only flaw is a SQL injection reaches exactly the
    A threshold, because the four other categories are untouched. Security is
    not one fifth of quality when it is broken.
    """
    for ceiling_score, ceiling_grade in sorted(config.SECURITY_GRADE_CEILING.items()):
        if security <= ceiling_score:
            return worse_grade(grade, ceiling_grade)
    return grade


def final_grade(total: float, security: int) -> str:
    """The grade actually reported: the total, capped by security."""
    return apply_security_ceiling(grade_for(total), security)


# --------------------------------------------------------------------------
# Coverage: what could actually be looked at
# --------------------------------------------------------------------------


def _available_detectors(path: str, semgrep_available: bool) -> set[str]:
    """Which detectors were able to run on this file."""
    available = {"metrics_text"}

    if path.endswith(".py"):
        available.update(config.PYTHON_ONLY_DETECTORS)

    extension = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if semgrep_available and extension in config.SEMGREP_EXTENSIONS:
        available.add("semgrep")

    return available


def coverage_for(category: str, available: set[str]) -> str:
    """Whether a category was fully looked at, partly, or not at all.

    A score of 20 is not a claim of coverage. A JavaScript file gets 20 for
    performance because nothing measured it — the report must say so rather
    than imply a clean bill of health.
    """
    expected = set(config.CATEGORY_DETECTORS[category])
    present = expected & available

    if not present:
        return config.COVERAGE_NONE
    if present == expected:
        return config.COVERAGE_FULL
    return config.COVERAGE_PARTIAL


# --------------------------------------------------------------------------
# Scoring one file
# --------------------------------------------------------------------------


def score_file(
    path: str,
    lines: int,
    findings: list[Finding],
    semgrep_available: bool = True,
) -> FileScore:
    """Score a single file across the five categories."""
    available = _available_detectors(path, semgrep_available)
    by_category: dict[str, list[Finding]] = {c: [] for c in config.CATEGORIES}
    for finding in findings:
        by_category.setdefault(finding.category, []).append(finding)

    scores: dict[str, CategoryScore] = {}

    for category in config.CATEGORIES:
        in_category = by_category.get(category, [])
        coverage = coverage_for(category, available)
        weight = total_weight(in_category)

        if category == "security":
            scores[category] = CategoryScore(
                score=security_score(in_category),
                coverage=coverage,
                finding_count=len(in_category),
                weight=weight,
                method="worst_finding",
            )
        else:
            density = density_of(weight, lines)
            scores[category] = CategoryScore(
                score=density_score(density),
                coverage=coverage,
                finding_count=len(in_category),
                weight=weight,
                method="density",
                density=round(density, 2),
            )

    total = sum(score.score for score in scores.values())
    top = min(findings, key=lambda f: SEVERITY_RANK.get(f.severity, 9)) if findings else None

    return FileScore(
        path=path,
        lines=lines,
        scores=scores,
        total=total,
        grade=final_grade(total, scores["security"].score),
        top_finding=top,
    )


# --------------------------------------------------------------------------
# Scoring a project
# --------------------------------------------------------------------------


def score_project(
    contents: dict[str, str],
    findings: list[Finding],
    semgrep_available: bool = True,
) -> ProjectScore:
    """Score a whole project.

    Deliberately NOT the average of the file scores: see the module
    docstring. Security takes the worst finding anywhere; the other
    categories use one density computed over the whole codebase, so a large
    clean file genuinely dilutes a small messy one.
    """
    if not contents:
        # No code is not bad code. Every category is reported as not
        # evaluated and no grade is invented; the API layer refuses an empty
        # submission rather than handing back a meaningless A.
        empty = {
            category: CategoryScore(
                score=config.MAX_CATEGORY_SCORE,
                coverage=config.COVERAGE_NONE,
                finding_count=0,
                weight=0,
                method="none",
            )
            for category in config.CATEGORIES
        }
        return ProjectScore(
            scores=empty,
            total=0,
            grade=None,
            files=[],
            worst_file=None,
            best_file=None,
            is_empty=True,
        )

    by_path: dict[str, list[Finding]] = {path: [] for path in contents}
    for finding in findings:
        by_path.setdefault(finding.path, []).append(finding)

    file_scores = [
        score_file(
            path=path,
            lines=len(content.splitlines()),
            findings=by_path.get(path, []),
            semgrep_available=semgrep_available,
        )
        for path, content in contents.items()
    ]

    total_lines = sum(file.lines for file in file_scores)
    available: set[str] = set()
    for path in contents:
        available |= _available_detectors(path, semgrep_available)

    by_category: dict[str, list[Finding]] = {c: [] for c in config.CATEGORIES}
    for finding in findings:
        by_category.setdefault(finding.category, []).append(finding)

    scores: dict[str, CategoryScore] = {}
    for category in config.CATEGORIES:
        in_category = by_category.get(category, [])
        coverage = coverage_for(category, available)
        weight = total_weight(in_category)

        if category == "security":
            scores[category] = CategoryScore(
                score=security_score(in_category),
                coverage=coverage,
                finding_count=len(in_category),
                weight=weight,
                method="worst_finding",
            )
        else:
            density = density_of(weight, total_lines)
            scores[category] = CategoryScore(
                score=density_score(density),
                coverage=coverage,
                finding_count=len(in_category),
                weight=weight,
                method="density",
                density=round(density, 2),
            )

    total = sum(score.score for score in scores.values())
    ranked = sorted(file_scores, key=lambda file: file.total)

    return ProjectScore(
        scores=scores,
        total=total,
        grade=final_grade(total, scores["security"].score),
        files=file_scores,
        worst_file=ranked[0].path if ranked else None,
        best_file=ranked[-1].path if ranked else None,
    )
