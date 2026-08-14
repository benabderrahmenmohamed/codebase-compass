"""Tests of the findings normaliser.

Semgrep runs as a subprocess here, so a few tests are slower than the rest of
the suite. They are worth it: this is where every detector meets.
"""

from analysis import findings, semgrep_runner

VULNERABLE = """import hashlib

PASSWORD = "admin123"


def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    print(query)
    return hashlib.md5(query.encode()).hexdigest()
"""

MESSY = """def process(rows):
    data = []
    for row in rows:
        for cell in row:
            if cell > 42:
                data.append(cell)
    return data
"""


def make(path="a.py", line=1, severity="low", category="readability", message="m"):
    return findings.Finding(
        path=path,
        line=line,
        severity=severity,
        category=category,
        message=message,
        suggestion="s",
        source="test",
        penalty=1,
    )


# ---------------------------------------------------------------- ranking


def test_the_worst_severity_comes_first():
    ranked = findings.rank(
        [
            make(severity="low"),
            make(severity="critical"),
            make(severity="medium"),
            make(severity="high"),
        ]
    )

    assert [f.severity for f in ranked] == ["critical", "high", "medium", "low"]


def test_equal_severities_are_ordered_by_file_then_line():
    ranked = findings.rank(
        [
            make(path="b.py", line=1),
            make(path="a.py", line=9),
            make(path="a.py", line=2),
        ]
    )

    assert [(f.path, f.line) for f in ranked] == [
        ("a.py", 2),
        ("a.py", 9),
        ("b.py", 1),
    ]


# ------------------------------------------------------------ deduplication


def test_an_exact_repeat_is_removed():
    unique = findings.deduplicate([make(), make()])

    assert len(unique) == 1


def test_two_different_problems_on_one_line_are_both_kept():
    """A long line can also hold a weak name: both are real."""
    unique = findings.deduplicate(
        [
            make(line=7, message="Line of 140 characters."),
            make(line=7, message="'data' describes nothing."),
        ]
    )

    assert len(unique) == 2


# ---------------------------------------------------------------- grouping


def test_findings_are_grouped_into_the_five_categories():
    grouped = findings.group_by_category(
        [make(category="security"), make(category="performance")]
    )

    assert set(grouped) == set(findings.CATEGORIES)
    assert len(grouped["security"]) == 1
    assert grouped["maintainability"] == []


def test_files_are_grouped_worst_affected_first():
    grouped = findings.group_by_file(
        [
            make(path="quiet.py"),
            make(path="noisy.py", line=1),
            make(path="noisy.py", line=2),
        ]
    )

    assert list(grouped) == ["noisy.py", "quiet.py"]


# ------------------------------------------------------------- collection


def test_every_detector_contributes():
    result = findings.collect({"app/bad.py": VULNERABLE, "app/messy.py": MESSY})

    sources = {finding.source for finding in result.findings}
    assert "semgrep" in sources
    assert "naming" in sources
    assert "metrics" in sources


def test_semgrep_findings_carry_the_right_file():
    result = findings.collect({"app/bad.py": VULNERABLE, "app/clean.py": "x = 1\n"})

    semgrep_paths = {f.path for f in result.findings if f.source == "semgrep"}
    assert semgrep_paths == {"app/bad.py"}


def test_a_clean_project_produces_nothing():
    result = findings.collect({"app/ok.py": "def add(a, b):\n    return a + b\n"})

    assert result.findings == []
    assert result.is_complete


def test_an_empty_project_is_handled():
    result = findings.collect({})

    assert result.findings == []
    assert result.semgrep_available


def test_the_result_is_ranked_worst_first():
    result = findings.collect({"app/bad.py": VULNERABLE})

    severities = [findings.SEVERITY_ORDER[f.severity] for f in result.findings]
    assert severities == sorted(severities)


def test_clone_findings_are_attached_to_the_right_file():
    original = (
        "def validate(address):\n"
        "    if not address:\n"
        "        return False\n"
        '    if "@" not in address:\n'
        "        return False\n"
        "    return True\n"
    )
    renamed = original.replace("validate", "check").replace("address", "mail")

    result = findings.collect({"a.py": original, "b.py": renamed})

    clone = [f for f in result.findings if f.source == "clones"]
    assert len(clone) == 1
    assert clone[0].path == "b.py"


# ------------------------------------------------------- visible degradation


def test_a_missing_semgrep_is_reported_not_hidden(monkeypatch):
    """An empty security section must never read as "all clear"."""
    semgrep_runner.clear_cache()
    monkeypatch.setattr(semgrep_runner, "find_semgrep", lambda: None)

    result = findings.collect({"app/messy.py": MESSY})

    assert result.semgrep_available is False
    assert result.semgrep_reason == "semgrep_missing"
    assert result.is_complete is False
    # The offline detectors still ran: the report is partial, not empty.
    assert result.findings


def test_without_semgrep_security_coverage_effectively_disappears(monkeypatch):
    """The reason visible degradation matters.

    Security and best-practice detection come almost entirely from Semgrep.
    Without it a genuinely vulnerable file produces no security findings at
    all — which would read as a clean bill of health if the report did not
    say the analysis was incomplete.
    """
    semgrep_runner.clear_cache()
    monkeypatch.setattr(semgrep_runner, "find_semgrep", lambda: None)

    result = findings.collect({"app/bad.py": VULNERABLE})

    assert [f for f in result.findings if f.category == "security"] == []
    assert result.is_complete is False


def test_a_complete_run_says_so():
    semgrep_runner.clear_cache()

    result = findings.collect({"app/ok.py": "def add(a, b):\n    return a + b\n"})

    assert result.is_complete


# -------------------------------------------------------------------- cap


def test_findings_beyond_the_cap_are_counted_not_hidden(monkeypatch):
    monkeypatch.setattr(findings, "MAX_FINDINGS", 3)
    monkeypatch.setattr(
        findings.semgrep_runner,
        "scan_project",
        lambda contents: semgrep_runner.SemgrepResult([], True),
    )
    long_lines = "\n".join(f"x{i} = '{'a' * 150}'" for i in range(10))

    result = findings.collect({"app/wide.py": long_lines})

    assert len(result.findings) == 3
    assert result.dropped > 0
    assert result.is_complete is False


def test_the_cap_never_drops_a_critical_finding(monkeypatch):
    monkeypatch.setattr(findings, "MAX_FINDINGS", 2)
    padding = "\n".join(f"y{i} = '{'a' * 150}'" for i in range(20))

    result = findings.collect({"app/bad.py": VULNERABLE + padding})

    assert result.findings[0].severity in ("critical", "high")
