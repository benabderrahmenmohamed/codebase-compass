"""Tests of context selection.

Pure functions, no network. This layer decides what the model sees, so the
properties that matter are: windows stay inside the file, they contain the
finding they exist for, and a tight budget drops the LEAST serious context.
"""

from analysis import context, findings, skeleton

FILE = "\n".join(f"line {number}" for number in range(1, 61)) + "\n"


def make(path="app/a.py", line=30, severity="low", category="readability"):
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


# ---------------------------------------------------------------- windows


def test_a_window_surrounds_its_finding():
    windows = context.build_windows({"app/a.py": FILE}, [make(line=30)], radius=8)

    assert len(windows) == 1
    window = windows[0]
    assert window.start_line == 22
    assert window.end_line == 38
    assert window.finding_lines == [30]


def test_a_window_never_runs_past_the_start_of_the_file():
    windows = context.build_windows({"app/a.py": FILE}, [make(line=2)], radius=8)

    assert windows[0].start_line == 1


def test_a_window_never_runs_past_the_end_of_the_file():
    windows = context.build_windows({"app/a.py": FILE}, [make(line=59)], radius=8)

    assert windows[0].end_line == 60


def test_lines_are_rendered_with_their_real_numbers():
    """The model quotes these back, and a later pass verifies them."""
    windows = context.build_windows({"app/a.py": FILE}, [make(line=30)], radius=2)

    assert "   30 | line 30" in windows[0].text
    assert "app/a.py lines 28-32" in windows[0].text


def test_overlapping_windows_are_merged():
    windows = context.build_windows(
        {"app/a.py": FILE}, [make(line=20), make(line=24)], radius=8
    )

    assert len(windows) == 1
    assert windows[0].finding_lines == [20, 24]


def test_distant_findings_get_separate_windows():
    windows = context.build_windows(
        {"app/a.py": FILE}, [make(line=5), make(line=50)], radius=3
    )

    assert len(windows) == 2


def test_a_finding_whose_file_is_absent_is_skipped():
    windows = context.build_windows({}, [make(path="ghost.py")])

    assert windows == []


def test_windows_are_ordered_worst_first():
    windows = context.build_windows(
        {"app/a.py": FILE},
        [make(line=5, severity="low"), make(line=50, severity="critical")],
        radius=2,
    )

    assert windows[0].worst_severity == "critical"


# ---------------------------------------------------------------- skeleton


def test_the_rendered_skeleton_has_no_function_bodies():
    source = (
        "def compute(rows):\n"
        '    """Add the rows up."""\n'
        "    secret_internal_detail = 42\n"
        "    return secret_internal_detail\n"
    )
    rendered = context.render_skeleton(skeleton.build({"app/a.py": source}))

    assert "compute" in rendered
    assert "Add the rows up." in rendered
    assert "secret_internal_detail" not in rendered


def test_the_skeleton_lists_entry_points_and_dependencies():
    project = {
        "main.py": "import requests\napp = FastAPI()\n",
        "models.py": "class Order:\n    pass\n",
    }
    rendered = context.render_skeleton(skeleton.build(project))

    assert "ENTRY POINTS: main.py" in rendered
    assert "requests" in rendered


# ----------------------------------------------------------------- payload


def build(project_findings, budget=context.DEFAULT_CHAR_BUDGET, radius=8):
    contents = {"app/a.py": FILE}
    return context.build_payload(
        contents, skeleton.build(contents), project_findings, char_budget=budget, radius=radius
    )


def test_a_payload_carries_the_map_and_the_windows():
    payload = build([make(line=30)])

    assert payload.skeleton_text
    assert len(payload.windows) == 1
    assert payload.is_complete


def test_a_tight_budget_drops_the_least_serious_windows():
    project_findings = [
        make(line=5, severity="low"),
        make(line=30, severity="low"),
        make(line=55, severity="critical"),
    ]

    payload = build(project_findings, budget=1, radius=2)

    assert payload.dropped_windows > 0
    assert payload.is_complete is False
    # Whatever survived must be the critical one.
    assert payload.windows[0].worst_severity == "critical"


def test_at_least_one_window_survives_any_budget():
    """A payload with no code at all would be useless."""
    payload = build([make(line=30)], budget=1)

    assert len(payload.windows) == 1


def test_findings_outside_the_kept_windows_are_dropped_too():
    """The model must never be asked about code it cannot see."""
    project_findings = [
        make(line=5, severity="low"),
        make(line=55, severity="critical"),
    ]

    payload = build(project_findings, budget=1, radius=2)

    assert [f.line for f in payload.findings] == [55]


def test_the_payload_reports_what_it_left_out():
    payload = build(
        [make(line=n, severity="low") for n in (3, 20, 40, 58)], budget=1, radius=1
    )
    rendered = context.render_payload(payload)

    assert "omitted" in rendered


def test_an_estimate_is_labelled_as_an_estimate_not_a_measurement():
    payload = build([make(line=30)])

    assert payload.estimated_tokens == payload.estimated_chars // 4
    assert payload.estimated_chars == len(payload.skeleton_text) + sum(
        len(window.text) for window in payload.windows
    )


def test_a_project_with_no_findings_still_sends_the_map():
    payload = build([])

    assert payload.windows == []
    assert payload.skeleton_text
    assert payload.is_complete
