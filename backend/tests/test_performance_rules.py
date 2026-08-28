"""The performance rule pack.

Performance was one of five scored categories resting on a single detector,
so a score of 20 there usually meant "one thing looked" rather than
"nothing is wrong". These rules close that gap.

Each test asserts two things: that the rule fires on the mistake, and that
it stays quiet on the correct version. The second half matters more. Three
plausible rules were written and deleted for failing it — len() in a loop
condition (O(1) in Python), open() in a loop (iterating filenames is
correct), and membership tests against small literals (scanning three items
beats building a set).
"""

import pathlib

import pytest

from analysis import findings

SAMPLES = pathlib.Path(__file__).parent / "samples"


def performance_findings(code: str, path: str = "sample.py"):
    collected = findings.collect({path: code})
    return [f for f in collected.findings if f.category == "performance"]


def rules_fired(code: str, path: str = "sample.py") -> set[str]:
    return {f.rule for f in performance_findings(code, path) if f.rule}


# --------------------------------------------------------------------------
# N+1: the highest-value rule in the pack
# --------------------------------------------------------------------------


def test_a_query_inside_a_loop_is_reported():
    code = (
        "def load(db, ids):\n"
        "    out = []\n"
        "    for i in ids:\n"
        "        out.append(db.execute('SELECT 1'))\n"
        "    return out\n"
    )
    assert "query-in-loop" in rules_fired(code)


def test_an_http_call_inside_a_loop_is_reported():
    code = (
        "import requests\n"
        "def enrich(users):\n"
        "    for u in users:\n"
        "        requests.get('https://x/' + u)\n"
    )
    assert "query-in-loop" in rules_fired(code)


def test_one_query_outside_a_loop_is_not_reported():
    code = "def load(db, ids):\n    return db.execute('SELECT 1', ids)\n"
    assert "query-in-loop" not in rules_fired(code)


def test_the_n_plus_one_rule_is_high_severity():
    """It is the usual reason an endpoint is slow in production."""
    code = (
        "def load(db, ids):\n"
        "    for i in ids:\n"
        "        db.execute('SELECT 1')\n"
    )
    hit = [f for f in performance_findings(code) if f.rule == "query-in-loop"][0]
    assert hit.severity == "high"


# --------------------------------------------------------------------------
# Quadratic string building — the AST detector
#
# Semgrep cannot express this: `$S += $X` is equally a numeric accumulator,
# which is fine. Telling them apart needs the type of $S.
# --------------------------------------------------------------------------


def test_a_string_grown_in_a_loop_is_reported():
    code = (
        "def build(rows):\n"
        "    out = ''\n"
        "    for r in rows:\n"
        "        out += str(r)\n"
        "    return out\n"
    )
    assert any("String grown" in f.message for f in performance_findings(code))


def test_a_numeric_accumulator_is_not_reported():
    """The rule that would have made this detector useless."""
    code = (
        "def total(rows):\n"
        "    n = 0\n"
        "    for r in rows:\n"
        "        n += r\n"
        "    return n\n"
    )
    assert not any("String grown" in f.message for f in performance_findings(code))


def test_string_concatenation_outside_a_loop_is_not_reported():
    code = "def join(a, b):\n    s = ''\n    s += a\n    return s\n"
    assert not any("String grown" in f.message for f in performance_findings(code))


def test_appending_to_a_list_is_the_correct_version_and_stays_quiet():
    code = (
        "def build(rows):\n"
        "    parts = []\n"
        "    for r in rows:\n"
        "        parts.append(str(r))\n"
        "    return ''.join(parts)\n"
    )
    assert not any("String grown" in f.message for f in performance_findings(code))


def test_a_while_loop_counts_too():
    code = (
        "def build(rows):\n"
        "    out = ''\n"
        "    i = 0\n"
        "    while i < 10:\n"
        "        out += str(i)\n"
        "        i += 1\n"
        "    return out\n"
    )
    assert any("String grown" in f.message for f in performance_findings(code))


# --------------------------------------------------------------------------
# The smaller rules
# --------------------------------------------------------------------------


def test_inserting_at_the_front_of_a_list_is_reported():
    assert "insert-at-front-of-list" in rules_fired("def f(xs, x):\n    xs.insert(0, x)\n")


def test_appending_to_the_end_is_not():
    assert "insert-at-front-of-list" not in rules_fired("def f(xs, x):\n    xs.append(x)\n")


def test_a_regex_compiled_in_a_loop_is_reported():
    code = (
        "import re\n"
        "def f(lines):\n"
        "    for line in lines:\n"
        "        p = re.compile('a')\n"
    )
    assert "regex-compiled-in-loop" in rules_fired(code)


def test_a_regex_compiled_once_is_not():
    code = (
        "import re\n"
        "P = re.compile('a')\n"
        "def f(lines):\n"
        "    for line in lines:\n"
        "        P.match(line)\n"
    )
    assert "regex-compiled-in-loop" not in rules_fired(code)


def test_row_by_row_pandas_iteration_is_reported():
    assert "pandas-row-iteration" in rules_fired("def f(df):\n    return df.iterrows()\n")


def test_a_membership_test_in_a_loop_is_reported():
    code = (
        "def f(records, allowed):\n"
        "    for r in records:\n"
        "        if r in allowed:\n"
        "            pass\n"
    )
    assert "membership-test-in-loop" in rules_fired(code)


def test_the_loop_header_itself_is_not_a_membership_test():
    """`for x in xs` contains the token `in` and is not a membership test."""
    code = "def f(xs):\n    for x in xs:\n        print(x)\n"
    assert "membership-test-in-loop" not in rules_fired(code)


# --------------------------------------------------------------------------
# JavaScript
# --------------------------------------------------------------------------


def test_awaiting_inside_a_loop_is_reported():
    code = (
        "export async function load(ids) {\n"
        "  for (const id of ids) {\n"
        "    await fetch(`/api/${id}`)\n"
        "  }\n"
        "}\n"
    )
    assert "await-in-loop" in rules_fired(code, "sample.js")


def test_awaiting_promise_all_once_is_the_correct_version():
    code = (
        "export async function load(ids) {\n"
        "  await Promise.all(ids.map((id) => fetch(`/api/${id}`)))\n"
        "}\n"
    )
    assert "await-in-loop" not in rules_fired(code, "sample.js")


def test_querying_the_dom_in_a_loop_is_reported():
    code = (
        "export function paint(rows) {\n"
        "  for (const row of rows) {\n"
        "    document.querySelector('#out').textContent = row\n"
        "  }\n"
        "}\n"
    )
    assert "dom-query-in-loop" in rules_fired(code, "sample.js")


# --------------------------------------------------------------------------
# The pack as a whole
# --------------------------------------------------------------------------


def test_every_rule_that_fires_carries_complete_scoring_metadata():
    """Scoring reads metadata rather than testing rule identifiers, so a
    rule missing it would be found and then silently score nothing.

    Asserted through the real path — the findings that actually come out
    — rather than by parsing the YAML. That needs no extra dependency and
    tests the property that matters: the metadata reaches scoring.
    """
    contents = {
        "slow_queries.py": (SAMPLES / "slow_queries.py").read_text(encoding="utf-8"),
        "slow_frontend.js": (SAMPLES / "slow_frontend.js").read_text(encoding="utf-8"),
    }
    collected = findings.collect(contents)
    assert collected.findings, "the samples should produce findings"

    for finding in collected.findings:
        assert finding.category, f"{finding.rule or finding.source} has no category"
        assert finding.severity, f"{finding.rule or finding.source} has no severity"
        assert finding.penalty is not None, f"{finding.rule} has no penalty"
        assert finding.suggestion, f"{finding.rule} has no suggestion"


def test_the_sample_file_triggers_the_whole_pack():
    """One realistic file exercising every rule, kept as a fixture so a
    change that silently stops a rule matching is caught."""
    code = (SAMPLES / "slow_queries.py").read_text(encoding="utf-8")
    fired = rules_fired(code, "slow_queries.py")

    for rule in (
        "query-in-loop",
        "insert-at-front-of-list",
        "regex-compiled-in-loop",
        "membership-test-in-loop",
        "pandas-row-iteration",
    ):
        assert rule in fired, f"{rule} no longer fires on the sample"


def test_the_javascript_sample_triggers_its_rules():
    code = (SAMPLES / "slow_frontend.js").read_text(encoding="utf-8")
    fired = rules_fired(code, "slow_frontend.js")

    assert "await-in-loop" in fired
    assert "dom-query-in-loop" in fired


def test_performance_is_scored_well_below_perfect_on_the_sample():
    """The point of the pack: this file used to score 20/20 for
    performance, because only nested loops were looked for."""
    from analysis import scoring

    code = (SAMPLES / "slow_queries.py").read_text(encoding="utf-8")
    contents = {"slow_queries.py": code}
    collected = findings.collect(contents)
    score = scoring.score_project(contents, collected.findings, collected.semgrep_available)

    assert score.scores["performance"].score < 20
