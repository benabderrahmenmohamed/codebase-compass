"""Layer 5: choosing what the model actually sees.

This is where cost is decided. The model never receives a codebase — it
receives:

  * a **skeleton**: the project map, signatures only, no function bodies;
  * **focus windows**: a few lines around each thing a detector already
    flagged.

A 500-line file with six findings sends roughly 100 lines instead of 500, and
those 100 lines are pre-selected as the ones that matter. That is what keeps
an analysis in the region of a few cents rather than a few dollars, and it
improves precision too: less irrelevant code to be distracted by.

Every line is sent with its REAL line number. The model quotes those numbers
back, and a later pass checks each one against the file — a claim about
line 340 of a 200-line file is dropped rather than shown.
"""

from typing import NamedTuple

from analysis.findings import Finding
from analysis.scoring import SEVERITY_RANK
from analysis.skeleton import ProjectSkeleton

# Lines of context on each side of a flagged line. Enough to see the
# surrounding function without pulling in the whole file.
DEFAULT_RADIUS = 8

# Two windows closer than this are merged rather than sent separately: the
# gap would cost more in repeated headers than in the lines themselves.
MERGE_GAP = 4

# Rough character budget for the whole payload. Characters, not tokens:
# `count_tokens` is an API call and needs a key, so it is used as the
# authority just before sending (see claude_client), while this cheap
# estimate keeps the payload sane offline.
DEFAULT_CHAR_BUDGET = 40_000

# How many findings the model is asked to EXPLAIN.
#
# This is not the same limit as the report's finding cap, and it exists for a
# different reason. The character budget bounds what we SEND; nothing bounded
# what the model had to WRITE, and writing is both the slow half and the
# expensive half — output was 93% of a measured bill. On a 55-file
# repository the model was handed 100 findings, tried to explain all of them,
# and hit the 120-second timeout: the deterministic report survived, and the
# one thing no other tool does was replaced by "the request timed out".
#
# A newcomer cannot act on a hundred explanations anyway. They can act on the
# worst fifteen. The findings are all still reported, ranked and counted —
# only the explanations are capped, and the count that went unexplained is
# reported rather than quietly dropped.
MAX_EXPLAINED_FINDINGS = 15

# Roughly four characters per token for source code. An estimate, never a
# measurement — and deliberately not tiktoken, which is OpenAI's tokenizer
# and undercounts Claude by 15-20%, far more on code.
CHARS_PER_TOKEN_ESTIMATE = 4

# The largest share of the budget the map may take.
#
# Measured on this project: an untrimmed skeleton took 84% of the payload and
# left room for 4 code windows out of 49. The map is context; the windows are
# the evidence. Splitting the budget explicitly keeps the map from crowding
# out the thing it is meant to introduce.
SKELETON_BUDGET_SHARE = 0.5

# Symbols worth showing first when a file has more than fits. Classes and
# functions describe what a file DOES; constants mostly describe how it is
# tuned, which matters less when orienting someone.
SYMBOL_PRIORITY = {"class": 0, "function": 1, "method": 2, "constant": 3}

DEFAULT_SYMBOLS_PER_FILE = 12

# Progressively tighter symbol limits, tried in order until the map fits.
SYMBOL_LIMIT_STEPS = (12, 8, 5, 3, 1, 0)


class Window(NamedTuple):
    """A slice of one file, with real line numbers attached."""

    path: str
    start_line: int
    end_line: int
    text: str
    finding_lines: list[int]
    worst_severity: str

    @property
    def line_count(self) -> int:
        return self.end_line - self.start_line + 1


class Payload(NamedTuple):
    """Everything the model will be given, and what was left out."""

    skeleton_text: str
    windows: list[Window]
    findings: list[Finding]
    estimated_chars: int
    dropped_windows: int
    # Findings ranked below the explanation cap. They appear in the report
    # in full; they were simply not sent for the model to write about.
    findings_not_explained: int = 0

    @property
    def estimated_tokens(self) -> int:
        """A rough estimate. count_tokens is the authority before sending."""
        return self.estimated_chars // CHARS_PER_TOKEN_ESTIMATE

    @property
    def is_complete(self) -> bool:
        return self.dropped_windows == 0


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------


def _merge_ranges(lines: list[int], radius: int, last_line: int) -> list[tuple[int, int]]:
    """Turn flagged line numbers into merged, in-bounds ranges."""
    ranges: list[tuple[int, int]] = []

    for line in sorted(set(lines)):
        start = max(1, line - radius)
        end = min(last_line, line + radius)

        if ranges and start <= ranges[-1][1] + MERGE_GAP:
            # Overlapping or near-touching: extend the previous range rather
            # than sending the same lines twice under two headers.
            previous_start, previous_end = ranges[-1]
            ranges[-1] = (previous_start, max(previous_end, end))
        else:
            ranges.append((start, end))

    return ranges


def _render(path: str, lines: list[str], start: int, end: int) -> str:
    """Render a slice with real line numbers, ready to paste into a prompt."""
    body = "\n".join(
        f"{number:>5} | {lines[number - 1]}" for number in range(start, end + 1)
    )
    return f"--- {path} lines {start}-{end} ---\n{body}"


def build_windows(
    contents: dict[str, str],
    findings: list[Finding],
    radius: int = DEFAULT_RADIUS,
) -> list[Window]:
    """One window per cluster of findings, worst first."""
    by_path: dict[str, list[Finding]] = {}
    for finding in findings:
        by_path.setdefault(finding.path, []).append(finding)

    windows: list[Window] = []

    for path, in_file in by_path.items():
        content = contents.get(path)
        if content is None:
            # A finding whose file is not in the payload cannot be shown.
            continue

        lines = content.splitlines()
        if not lines:
            continue

        for start, end in _merge_ranges([f.line for f in in_file], radius, len(lines)):
            inside = [f for f in in_file if start <= f.line <= end]
            if not inside:
                continue
            worst = min(inside, key=lambda f: SEVERITY_RANK.get(f.severity, 9))
            windows.append(
                Window(
                    path=path,
                    start_line=start,
                    end_line=end,
                    text=_render(path, lines, start, end),
                    finding_lines=sorted(f.line for f in inside),
                    worst_severity=worst.severity,
                )
            )

    # Worst first, so that if the budget runs out it is the least serious
    # windows that are dropped.
    return sorted(
        windows,
        key=lambda window: (
            SEVERITY_RANK.get(window.worst_severity, 9),
            window.path,
            window.start_line,
        ),
    )


# --------------------------------------------------------------------------
# Skeleton rendering
# --------------------------------------------------------------------------


def _select_symbols(symbols, limit: int):
    """The `limit` most orienting symbols, back in line order."""
    ranked = sorted(symbols, key=lambda s: (SYMBOL_PRIORITY.get(s.kind, 9), s.line))
    return sorted(ranked[:limit], key=lambda symbol: symbol.line)


def _render_skeleton(skeleton: ProjectSkeleton, symbols_per_file: int) -> str:
    parts: list[str] = []

    if skeleton.entry_points:
        parts.append("ENTRY POINTS: " + ", ".join(skeleton.entry_points))
    if skeleton.external_dependencies:
        parts.append("DEPENDENCIES: " + ", ".join(skeleton.external_dependencies))

    parts.append("")
    parts.append("FILES:")

    for file in skeleton.files:
        importers = len(skeleton.imported_by.get(file.path, []))
        header = f"  {file.path} ({file.lines} lines, imported by {importers})"
        if file.parse_error:
            parts.append(header + "  [could not be parsed]")
            continue
        parts.append(header)

        imports = skeleton.imports_graph.get(file.path, [])
        if imports:
            parts.append(f"      imports: {', '.join(imports)}")

        shown = _select_symbols(file.symbols, symbols_per_file)
        for symbol in shown:
            doc = f"  # {symbol.doc}" if symbol.doc else ""
            parts.append(f"      L{symbol.line} {symbol.kind} {symbol.signature}{doc}")

        hidden = len(file.symbols) - len(shown)
        if hidden > 0:
            parts.append(f"      ... {hidden} more symbols")

    return "\n".join(parts)


def render_skeleton(
    skeleton: ProjectSkeleton,
    max_symbols_per_file: int = DEFAULT_SYMBOLS_PER_FILE,
    char_budget: int | None = None,
) -> str:
    """The project map as compact text, trimmed to fit a budget.

    Signatures and first docstring lines only — never a function body. This
    is the difference between a few thousand characters and a few hundred
    thousand.

    When a budget is given, the map is re-rendered with progressively fewer
    symbols per file until it fits. Files, imports and entry points always
    survive: losing a file from the map is worse than losing its constants,
    because a file nobody mentions cannot be asked about.
    """
    text = _render_skeleton(skeleton, max_symbols_per_file)
    if char_budget is None or len(text) <= char_budget:
        return text

    for limit in SYMBOL_LIMIT_STEPS:
        if limit > max_symbols_per_file:
            continue
        text = _render_skeleton(skeleton, limit)
        if len(text) <= char_budget:
            return text

    return text


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------


def build_payload(
    contents: dict[str, str],
    skeleton: ProjectSkeleton,
    findings: list[Finding],
    char_budget: int = DEFAULT_CHAR_BUDGET,
    radius: int = DEFAULT_RADIUS,
    max_explained: int = MAX_EXPLAINED_FINDINGS,
) -> Payload:
    """Assemble the skeleton plus as many windows as the budget allows.

    Windows are added worst-first, so a budget that runs out drops the least
    serious context — never a critical finding's surroundings. Whatever is
    dropped is counted and reported, never silently discarded.

    Two different limits apply, for two different reasons. `max_explained`
    bounds how many findings the model is asked to write about, because
    output is what costs time and money. `char_budget` bounds how much code
    is sent to support them.
    """
    # The map gets a fixed share at most, so it can never crowd out the code
    # windows it exists to introduce.
    skeleton_text = render_skeleton(
        skeleton, char_budget=int(char_budget * SKELETON_BUDGET_SHARE)
    )
    # `findings` arrives ranked worst-first, so the head of the list is the
    # part worth explaining. Trimming here rather than after window building
    # shrinks the input too: fewer findings need fewer windows around them.
    explained = findings[:max_explained] if max_explained else findings
    not_explained = len(findings) - len(explained)

    ranked = build_windows(contents, explained, radius)

    used = len(skeleton_text)
    kept: list[Window] = []
    dropped = 0

    for window in ranked:
        cost = len(window.text)
        if used + cost > char_budget and kept:
            # Keep at least one window even on an absurdly small budget:
            # a payload with no code at all is useless.
            dropped += 1
            continue
        used += cost
        kept.append(window)

    # Restore file/line order for readability once selection is done.
    kept.sort(key=lambda window: (window.path, window.start_line))

    shown = {(window.path, line) for window in kept for line in window.finding_lines}
    kept_findings = [f for f in explained if (f.path, f.line) in shown]

    return Payload(
        skeleton_text=skeleton_text,
        windows=kept,
        findings=kept_findings,
        estimated_chars=used,
        dropped_windows=dropped,
        findings_not_explained=not_explained,
    )


def render_payload(payload: Payload) -> str:
    """The whole payload as one string, ready for a prompt."""
    sections = ["## PROJECT MAP", payload.skeleton_text]

    if payload.windows:
        sections.append("\n## CODE AROUND EACH FINDING")
        sections.extend(window.text for window in payload.windows)

    if payload.dropped_windows:
        sections.append(
            f"\n[{payload.dropped_windows} lower-severity windows omitted "
            "to stay within budget]"
        )

    return "\n\n".join(sections)
