"""Tests of the three per-file detectors: metrics, naming, clones.

All offline, all parsing only.
"""

from analysis import clones, metrics, naming


def lines_of(findings):
    return sorted(finding.line for finding in findings)


def messages_of(findings):
    return " | ".join(finding.message for finding in findings)


# ==========================================================================
# metrics
# ==========================================================================


def test_a_long_line_is_measured():
    content = "x = 1\n" + "y = '" + "a" * 200 + "'\n"

    findings = metrics.measure("app/a.py", content)

    assert any("characters" in f.message for f in findings)
    assert any(f.category == "readability" for f in findings)


def test_a_short_file_measures_nothing():
    findings = metrics.measure("app/a.py", "def add(a, b):\n    return a + b\n")

    assert findings == []


def test_a_long_function_is_measured():
    body = "\n".join(f"    step_{i} = {i}" for i in range(60))
    content = f"def process():\n{body}\n    return 1\n"

    findings = metrics.measure("app/a.py", content)

    assert any("lines long" in f.message for f in findings)
    assert any(f.category == "maintainability" for f in findings)


def test_deep_nesting_is_measured():
    content = (
        "def deep(items):\n"
        "    for a in items:\n"
        "        if a:\n"
        "            while a:\n"
        "                with open('f') as handle:\n"
        "                    return handle\n"
    )

    findings = metrics.measure("app/a.py", content)

    assert any("nests" in f.message for f in findings)


def test_nested_loops_are_measured_as_performance():
    content = "def slow(rows):\n    for r in rows:\n        for c in r:\n            print(c)\n"

    findings = metrics.measure("app/a.py", content)

    performance = [f for f in findings if f.category == "performance"]
    assert len(performance) == 1
    assert performance[0].line == 3


def test_two_sibling_loops_are_not_nested():
    content = (
        "def fine(rows):\n"
        "    for r in rows:\n"
        "        print(r)\n"
        "    for r in rows:\n"
        "        print(r)\n"
    )

    findings = metrics.measure("app/a.py", content)

    assert [f for f in findings if f.category == "performance"] == []


def test_a_def_inside_a_string_is_not_measured():
    """Text matching would count this; syntax analysis does not."""
    body = "\\n".join(f"    x{i} = {i}" for i in range(60))
    content = f'EXAMPLE = "def fake():\\n{body}"\n'

    findings = metrics.measure("app/a.py", content)

    assert [f for f in findings if "lines long" in f.message] == []


def test_a_file_that_does_not_parse_still_gets_text_measurements():
    content = "def broken(:\n" + "z = '" + "a" * 200 + "'\n"

    findings = metrics.measure("app/a.py", content)

    assert any("characters" in f.message for f in findings)


# ==========================================================================
# naming
# ==========================================================================


def test_placeholder_names_are_flagged():
    findings = naming.analyse("app/a.py", "data = load()\ntmp = 1\nresult = 2\n")

    flagged = {f.symbol for f in findings}
    assert {"data", "tmp", "result"} <= flagged


def test_very_short_names_are_flagged():
    findings = naming.find_weak_names("ab = compute()\n")

    assert findings[0].symbol == "ab"


def test_loop_counters_are_tolerated():
    findings = naming.find_weak_names("for i in range(3):\n    j = i\n")

    assert findings == []


def test_numbered_names_are_flagged():
    findings = naming.find_weak_names("str1 = 'a'\nstr2 = 'b'\n")

    assert {f.symbol for f in findings} == {"str1", "str2"}


def test_a_name_inside_a_string_is_not_flagged():
    """The lesson from the entry-point bug, applied here from the start."""
    findings = naming.find_weak_names('EXAMPLE = "data = 1"\n')

    assert [f for f in findings if f.symbol == "data"] == []


def test_magic_numbers_are_flagged():
    findings = naming.find_magic_numbers("if age > 17:\n    pass\n")

    assert findings[0].symbol == "17"


def test_common_numbers_are_not_flagged():
    findings = naming.find_magic_numbers("x = 0\ny = 1\nz = -1\nw = 2\n")

    assert findings == []


def test_a_number_given_a_named_constant_is_not_flagged():
    findings = naming.find_magic_numbers("LEGAL_AGE = 17\n")

    assert findings == []


def test_boolean_parameters_are_flagged():
    findings = naming.find_boolean_parameters(
        "def create(name, notify=True):\n    return name\n"
    )

    assert findings[0].symbol == "create.notify"


def test_unused_variables_are_flagged():
    content = "def run():\n    used = 1\n    forgotten = 2\n    return used\n"

    findings = naming.find_unused_variables(content)

    assert [f.symbol for f in findings] == ["forgotten"]


def test_underscore_variables_are_tolerated():
    findings = naming.find_unused_variables("def run():\n    _ignored = 1\n    return 2\n")

    assert findings == []


def test_namedtuple_fields_are_not_unused_variables():
    """Found by running this detector on the project itself.

    `path: str` inside a NamedTuple is a field DECLARATION, not a variable.
    Treating declarations as assignments produced 71 false positives across
    14 files and buried every real finding.
    """
    content = (
        "from typing import NamedTuple\n\n"
        "class Pair(NamedTuple):\n"
        "    first_path: str\n"
        "    second_path: str\n"
    )

    assert naming.find_unused_variables(content) == []


def test_module_level_names_are_not_unused_variables():
    """A module constant may be imported by another file we cannot see."""
    assert naming.find_unused_variables("MAX_ITEMS = 50\n") == []


def test_only_function_scope_counts_as_unused():
    content = (
        "SHARED = 1\n"
        "def run():\n"
        "    local_leftover = 2\n"
        "    return SHARED\n"
    )

    findings = naming.find_unused_variables(content)

    assert [f.symbol for f in findings] == ["local_leftover"]


def test_ordinary_field_names_are_not_treated_as_placeholders():
    """`content`, `response` and `items` are usually the right name."""
    findings = naming.find_weak_names(
        "content = read()\nresponse = call()\nitems = load()\n"
    )

    assert findings == []


def test_javascript_is_left_alone_for_now():
    """Guessing names from text without a parser causes false positives."""
    assert naming.analyse("front/a.js", "const data = 1\n") == []


def test_each_weak_name_is_reported_once():
    findings = naming.find_weak_names("data = 1\ndata = 2\ndata = 3\n")

    assert len(findings) == 1


# ==========================================================================
# clones
# ==========================================================================


ORIGINAL = """def validate_email(address):
    if not address:
        return False
    if "@" not in address:
        return False
    return True
"""

# Same code, different formatting and comments.
EXACT_COPY = """def validate_email(address):
    # checks the address

    if not address:
        return False

    if "@" not in address:
        return False
    return True
"""

# Same structure, every name changed.
RENAMED_COPY = """def check_mail(mail):
    if not mail:
        return False
    if "@" not in mail:
        return False
    return True
"""

DIFFERENT = """def total_price(items):
    total = 0
    for item in items:
        total += item.price
    return total
"""


def test_an_exact_duplicate_is_found():
    pairs = clones.find_pairs({"a.py": ORIGINAL, "b.py": EXACT_COPY})

    assert len(pairs) == 1
    assert pairs[0].kind == "exact"


def test_a_renamed_duplicate_is_found_structurally():
    pairs = clones.find_pairs({"a.py": ORIGINAL, "b.py": RENAMED_COPY})

    assert len(pairs) == 1
    assert pairs[0].kind == "structural"
    assert {pairs[0].first_name, pairs[0].second_name} == {
        "validate_email",
        "check_mail",
    }


def test_different_functions_are_not_reported():
    assert clones.find_pairs({"a.py": ORIGINAL, "b.py": DIFFERENT}) == []


def test_trivial_functions_do_not_collide():
    """Every two-line getter in a project would otherwise match every other."""
    tiny = {
        "a.py": "def get_name(self):\n    return self.name\n",
        "b.py": "def get_age(self):\n    return self.age\n",
    }

    assert clones.find_pairs(tiny) == []


def test_duplicates_inside_one_file_are_found():
    pairs = clones.find_pairs({"utils.py": ORIGINAL + "\n\n" + RENAMED_COPY})

    assert len(pairs) == 1
    assert pairs[0].first_path == pairs[0].second_path


def test_a_pair_is_reported_only_once():
    """An exact duplicate is also a structural one: report it as exact."""
    pairs = clones.find_pairs({"a.py": ORIGINAL, "b.py": EXACT_COPY})

    assert len(pairs) == 1


def test_the_finding_names_both_copies_and_the_file():
    findings = clones.analyse({"a.py": ORIGINAL, "b.py": RENAMED_COPY})

    assert len(findings) == 1
    assert "validate_email" in findings[0].message
    assert "a.py" in findings[0].message
    assert findings[0].path == "b.py"
    assert findings[0].category == "maintainability"


def test_a_file_that_does_not_parse_is_skipped():
    assert clones.find_pairs({"broken.py": "def f(:\n ???\n"}) == []
