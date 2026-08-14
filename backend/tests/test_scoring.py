"""Tests of the scoring layer.

Two properties matter most and are asserted directly:
  * security is capped by the WORST finding, anywhere in the project;
  * the project score is NOT the average of the file scores.
"""

import pathlib

import pytest

from analysis import findings, scoring
from analysis import scoring_config as config

SAMPLES = pathlib.Path(__file__).parent / "samples"


def load(name: str) -> str:
    return (SAMPLES / f"{name}.py").read_text(encoding="utf-8")


def make(severity="low", category="readability", path="a.py", line=1):
    return findings.Finding(
        path=path,
        line=line,
        severity=severity,
        category=category,
        message="m",
        suggestion="s",
        source="test",
        penalty=1,
    )


def score_sample(name: str) -> scoring.ProjectScore:
    content = load(name)
    contents = {f"{name}.py": content}
    collection = findings.collect(contents)
    return scoring.score_project(
        contents, collection.findings, collection.semgrep_available
    )


# ---------------------------------------------------------------- the curve


def test_the_density_curve_follows_the_configured_table():
    for threshold, expected in config.DENSITY_TO_SCORE:
        assert scoring.density_score(threshold) == expected


def test_a_density_above_the_last_threshold_hits_the_floor():
    last_threshold = config.DENSITY_TO_SCORE[-1][0]

    assert scoring.density_score(last_threshold + 1) == config.DENSITY_FLOOR_SCORE


def test_density_is_weighted_findings_per_hundred_lines():
    # one medium finding (weight 3) in 100 lines -> density 3
    assert scoring.density_of(3, 100) == pytest.approx(3.0)
    # the same finding in 50 lines is twice as dense
    assert scoring.density_of(3, 50) == pytest.approx(6.0)


# -------------------------------------------------------------- grade bands


@pytest.mark.parametrize(
    "total,expected",
    [
        (100, "A"),
        (85, "A"),  # exactly on the boundary
        (84.9, "B"),
        (70, "B"),
        (69.9, "C"),
        (55, "C"),
        (54.9, "D"),
        (40, "D"),
        (39, "E"),
        (0, "E"),
    ],
)
def test_grade_boundaries(total, expected):
    assert scoring.grade_for(total) == expected


# ------------------------------------------------------------ security cap


@pytest.mark.parametrize(
    "severity,expected",
    [
        ("critical", 5),
        ("high", 10),
        ("medium", 14),
        ("low", 17),
    ],
)
def test_security_is_set_by_the_worst_finding(severity, expected):
    assert scoring.security_score([make(severity=severity)]) == expected


def test_no_security_finding_scores_full_marks():
    assert scoring.security_score([]) == config.SECURITY_SCORE_WHEN_CLEAN


def test_many_low_findings_never_outweigh_one_critical():
    """Volume must not beat severity: that would teach the wrong lesson."""
    ten_low = [make(severity="low") for _ in range(10)]
    one_critical = [make(severity="critical")]

    assert scoring.security_score(ten_low) > scoring.security_score(one_critical)


def test_one_critical_finding_caps_a_whole_ten_file_project():
    contents = {f"file{i}.py": "x = 1\n" * 50 for i in range(10)}
    project_findings = [make(severity="critical", category="security", path="file3.py")]

    result = scoring.score_project(contents, project_findings)

    assert result.scores["security"].score <= 5


# -------------------------------------------------------- density dilution


def test_the_same_findings_score_worse_in_a_smaller_file():
    """Three medium findings in 30 lines vs the same three in 500."""
    three_medium = [make(severity="medium", category="readability") for _ in range(3)]

    small = scoring.score_file("small.py", 30, three_medium)
    large = scoring.score_file("large.py", 500, three_medium)

    assert small.scores["readability"].score < large.scores["readability"].score


# --------------------------------------------- aggregation is not averaging


def test_the_project_score_is_not_the_average_of_the_file_scores():
    """A large clean file must dilute a small messy one.

    Averaging file totals would treat a 20-line disaster and a 2000-line
    clean file as equals. Density over the whole project does not.
    """
    contents = {
        "tiny_mess.py": "x = 1\n" * 20,
        "big_clean.py": "y = 2\n" * 2000,
    }
    project_findings = [
        make(severity="medium", category="readability", path="tiny_mess.py", line=i)
        for i in range(1, 8)
    ]

    result = scoring.score_project(contents, project_findings)
    average_of_files = sum(file.total for file in result.files) / len(result.files)

    assert result.total != pytest.approx(average_of_files)
    # Our method: the big clean file dilutes, so the project beats the average.
    assert result.total > average_of_files


def test_the_worst_and_best_files_are_reported():
    contents = {"good.py": "x = 1\n" * 40, "bad.py": "y = 2\n" * 40}
    project_findings = [
        make(severity="critical", category="readability", path="bad.py", line=i)
        for i in range(1, 6)
    ]

    result = scoring.score_project(contents, project_findings)

    assert result.worst_file == "bad.py"
    assert result.best_file == "good.py"


# ------------------------------------------------------------- edge cases


def test_an_empty_file_does_not_divide_by_zero():
    result = scoring.score_file("empty.py", 0, [])

    assert result.total == 100


def test_an_empty_project_gets_no_grade():
    """No code is not good code, so no grade is invented.

    The API refuses an empty submission rather than returning an A that
    would be both meaningless and trivially gameable.
    """
    result = scoring.score_project({}, [])

    assert result.is_empty
    assert result.grade is None
    assert all(
        score.coverage == config.COVERAGE_NONE for score in result.scores.values()
    )


def test_scoring_is_deterministic():
    contents = {"a.py": load("messy_readability")}
    collection = findings.collect(contents)

    first = scoring.score_project(contents, collection.findings)
    second = scoring.score_project(contents, collection.findings)

    assert first.total == second.total
    assert {c: s.score for c, s in first.scores.items()} == {
        c: s.score for c, s in second.scores.items()
    }


# ---------------------------------------------------------------- coverage


def test_a_score_of_twenty_is_not_a_claim_of_coverage():
    """A JS file gets 20 for performance because nothing measured it."""
    result = scoring.score_file("front/app.js", 50, [])

    assert result.scores["performance"].score == 20
    assert result.scores["performance"].coverage == config.COVERAGE_NONE


def test_a_python_file_is_fully_covered_when_semgrep_ran():
    result = scoring.score_file("app/main.py", 50, [], semgrep_available=True)

    assert all(
        score.coverage == config.COVERAGE_FULL for score in result.scores.values()
    )


def test_losing_semgrep_downgrades_security_coverage():
    result = scoring.score_file("app/main.py", 50, [], semgrep_available=False)

    assert result.scores["security"].coverage == config.COVERAGE_NONE
    assert result.scores["best_practices"].coverage == config.COVERAGE_PARTIAL


# ---------------------------------------------------------------- samples


def test_the_clean_sample_scores_top_marks():
    result = score_sample("clean")

    assert result.scores["security"].score == 20
    assert result.grade == "A"


def test_the_vulnerable_sample_is_capped_and_graded_low():
    result = score_sample("bad_security")

    assert result.scores["security"].score <= 5
    assert result.grade in ("D", "E")


def test_the_messy_sample_loses_readability():
    result = score_sample("messy_readability")

    assert result.scores["readability"].score < 20


def test_the_tangled_sample_loses_maintainability():
    result = score_sample("tangled_maintainability")

    assert result.scores["maintainability"].score < 20


def test_the_slow_sample_loses_performance():
    result = score_sample("slow_performance")

    assert result.scores["performance"].score < 20
