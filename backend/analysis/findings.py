"""Layer 3d: one finding type for every detector.

Semgrep, metrics, naming and clones each produce their own shape. Everything
downstream — scoring, the report, the LLM payload — should deal with exactly
one type. That is this module's job: normalise, deduplicate, rank, cap.

It is also where degradation becomes visible. If Semgrep could not run, the
result says so, so the report can state that the security analysis is
incomplete rather than showing a confident 20/20.
"""

from typing import NamedTuple

from analysis import clones, metrics, naming, semgrep_runner

# Worst first. Used for ranking and for deciding what survives the cap.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

CATEGORIES = (
    "security",
    "readability",
    "maintainability",
    "performance",
    "best_practices",
)

# A report nobody can read is not a report. Anything beyond this is counted
# and announced, never silently dropped.
MAX_FINDINGS = 100


class Finding(NamedTuple):
    """One problem, whichever detector found it."""

    path: str
    line: int
    severity: str
    category: str
    message: str
    suggestion: str
    source: str
    penalty: int
    symbol: str | None = None
    rule: str | None = None


class Collection(NamedTuple):
    """Every finding for a project, plus what could not be analysed."""

    findings: list[Finding]
    dropped: int
    semgrep_available: bool
    semgrep_reason: str | None = None

    @property
    def is_complete(self) -> bool:
        """False when part of the analysis could not run."""
        return self.semgrep_available and self.dropped == 0


def _from_semgrep(raw: dict) -> Finding:
    return Finding(
        path=raw.get("path", ""),
        line=raw.get("line", 1),
        severity=raw.get("severity", "medium"),
        category=raw.get("category", "best_practices"),
        message=raw.get("message", ""),
        suggestion=raw.get("suggestion", ""),
        source="semgrep",
        penalty=raw.get("penalty", 3),
        rule=raw.get("rule"),
    )


def _from_detector(path: str, raw) -> Finding:
    """Convert a Measurement, NameFinding or CloneFinding into a Finding.

    They already share the same field names, so this is a copy with the path
    attached — the detectors work one file at a time and do not carry it.
    """
    return Finding(
        path=getattr(raw, "path", None) or path,
        line=raw.line,
        severity=raw.severity,
        category=raw.category,
        message=raw.message,
        suggestion=raw.suggestion,
        source=raw.source,
        penalty=raw.penalty,
        symbol=getattr(raw, "symbol", None),
    )


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove exact repeats.

    The key is deliberately narrow — path, line, category AND message. A
    single line can legitimately carry several distinct problems (a long line
    that also holds a weak name), and a broader key would silently merge
    them. Today the detectors barely overlap, so this only removes genuine
    repeats; it is here so that adding a detector later cannot double-report.
    """
    seen: set[tuple] = set()
    unique: list[Finding] = []

    for finding in findings:
        key = (finding.path, finding.line, finding.category, finding.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)

    return unique


def rank(findings: list[Finding]) -> list[Finding]:
    """Worst first, then by file and line so the order is stable."""
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, 9),
            finding.path,
            finding.line,
        ),
    )


def collect(contents: dict[str, str]) -> Collection:
    """Run every detector over a project and return one ranked list.

    Ranking happens before the cap, so a critical finding is never dropped
    in favour of a long line.
    """
    scan = semgrep_runner.scan_project(contents)

    findings: list[Finding] = [_from_semgrep(raw) for raw in scan.findings]

    for path, content in contents.items():
        for measurement in metrics.measure(path, content):
            findings.append(_from_detector(path, measurement))
        for name_finding in naming.analyse(path, content):
            findings.append(_from_detector(path, name_finding))

    for clone in clones.analyse(contents):
        findings.append(_from_detector(clone.path, clone))

    ranked = rank(deduplicate(findings))
    dropped = max(0, len(ranked) - MAX_FINDINGS)

    return Collection(
        findings=ranked[:MAX_FINDINGS],
        dropped=dropped,
        semgrep_available=scan.available,
        semgrep_reason=scan.reason,
    )


def group_by_category(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Findings sorted into the five scored categories."""
    grouped: dict[str, list[Finding]] = {category: [] for category in CATEGORIES}
    for finding in findings:
        grouped.setdefault(finding.category, []).append(finding)
    return grouped


def group_by_file(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Findings sorted by file, worst-affected first."""
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.path, []).append(finding)
    return dict(
        sorted(grouped.items(), key=lambda item: -len(item[1]))
    )
