"""Layer 6: asking Claude for meaning.

The model is never asked to find problems. Detectors already did that. It is
asked the questions only understanding can answer:

  1. what does this badly-named symbol actually hold, and what should it be
     called?
  2. why does this finding matter, how is it fixed, what does it teach?
  3. in what order should someone read these files?
  4. what does the analysis raise that it cannot settle?

Three properties make this layer safe to depend on:

* **Structured output.** The SDK validates the answer against a Pydantic
  model, so a malformed reply is an error at the boundary, not corrupted data
  three layers later.
* **Verification.** Every path, line and symbol the model returns is checked
  against the real code. A claim about line 340 of a 200-line file is
  dropped, not displayed. Models describe architecture that does not exist;
  this is the cheapest possible defence.
* **Degradation.** No key, no network, a timeout, an over-budget payload or a
  safety refusal all return a result that says so. The deterministic report
  is always still there.
"""

import os
from typing import NamedTuple

from analysis.context import Payload
from analysis.skeleton import ProjectSkeleton
from schemas import ClaudeReport

# One constant, one file. Cheaper tiers exist (Sonnet 5 at $3/$15 per MTok,
# Haiku 4.5 at $1/$5) and that is a deliberate choice to make, not a default
# to drift into.
MODEL = "claude-opus-5"

# Thinking counts against max_tokens on this model, so the ceiling has to
# leave room for both the reasoning and the report.
MAX_TOKENS = 16_000

# Refuse to send a payload larger than this. count_tokens is the authority —
# the character estimate in context.py is only a pre-filter.
MAX_INPUT_TOKENS = 60_000

REQUEST_TIMEOUT_SECONDS = 120.0

# Dollars per million tokens, for claude-opus-5. Used only to show the user
# what a run cost; the bill itself comes from Anthropic.
#
# Measured on a 47-line project: input 1,212 fresh + 2,098 cached, output
# 3,617. Output was 93% of the cost. Focus windows shrink the INPUT, which
# turns out to be the cheap half — the bill is what the model WRITES, and
# that scales with how many findings it has to explain.
PRICE_PER_MTOK_INPUT = 5.0
PRICE_PER_MTOK_CACHED_INPUT = 0.5
PRICE_PER_MTOK_OUTPUT = 25.0

# Kept out of the system prompt on purpose: anything that changes between
# requests must live BELOW the cache breakpoint, or the cache never hits.
SYSTEM_PROMPT = """You help a developer understand a codebase they did not write.

You are given a PROJECT MAP (file tree, imports, signatures — no function \
bodies) and CODE WINDOWS (a few lines around each problem that automated \
detectors already found).

Your job is NOT to find problems. Rules already did that. Your job is to \
supply meaning:

1. SYMBOLS TO CLARIFY. For each badly-named symbol you were shown, read the \
surrounding code and say what the value ACTUALLY holds, then propose a name \
that says it. Example: `x` holds the token expiry date in UTC, so it should \
be `expiry_date`. This is translation, not criticism — write it for someone \
who is not yet able to work that out alone.

2. EXPLAINED FINDINGS. For each finding, say what the real consequence is, \
how to fix it, and what idea it teaches. If a finding looks wrong to you — \
the rule fired but the code is fine — mark it as a likely false positive and \
say why.

3. READING ORDER. Given the map, say which files to read first and why each \
one at that point.

4. QUESTIONS FOR THE TEAM. Things the analysis raises but cannot settle: \
architectural decisions, inconsistencies, anything that needs a human who \
knows the history.

Rules you must follow:

* Only ever refer to files, lines and symbols that appear in what you were \
given. Never invent a path, a function or a line number. If you cannot see \
something, say so instead of guessing.
* Every line number you cite must be one that was shown to you.
* Write plainly, for a competent developer new to this code. No preamble, no \
flattery, no restating the question.
* Prefer saying less over saying something you cannot support from the code \
in front of you."""


# Failures worth trying again: the request was fine, the service was not.
# Everything else is permanent — retrying a malformed request or a refusal
# just spends money to fail identically.
RETRYABLE_REASONS = frozenset(
    {"timeout", "rate_limited", "network_error", "server_error"}
)


class ClaudeResult(NamedTuple):
    """The model's answer, or a clear statement of why there isn't one."""

    report: ClaudeReport | None
    available: bool
    reason: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    dropped_claims: int = 0

    @property
    def used_cache(self) -> bool:
        return self.cache_read_tokens > 0

    @property
    def estimated_cost_usd(self) -> float:
        """What this call cost, in dollars.

        An estimate for display, not an invoice: it uses the list prices
        above and ignores anything Anthropic may apply on top.
        """
        return (
            self.input_tokens / 1e6 * PRICE_PER_MTOK_INPUT
            + self.cache_read_tokens / 1e6 * PRICE_PER_MTOK_CACHED_INPUT
            + self.output_tokens / 1e6 * PRICE_PER_MTOK_OUTPUT
        )

    @property
    def is_retryable(self) -> bool:
        """Whether trying again could plausibly succeed.

        The caller needs this to tell "the service was busy" from "this
        request will never work". Collapsing both into one error means either
        retrying forever on a permanent failure, or giving up on a temporary
        one.
        """
        return self.reason in RETRYABLE_REASONS


def classify_error(error: BaseException) -> str:
    """Turn an SDK exception into a stable reason string.

    Imported lazily so this module still works when the SDK is absent.

    Order matters: APITimeoutError subclasses APIConnectionError, so a
    timeout checked second would be reported as a generic network error.
    """
    try:
        import anthropic
    except ImportError:  # pragma: no cover - SDK is installed in this project
        return f"api_error:{type(error).__name__}"

    if isinstance(error, anthropic.APITimeoutError):
        return "timeout"
    if isinstance(error, anthropic.RateLimitError):
        return "rate_limited"
    if isinstance(error, anthropic.APIConnectionError):
        return "network_error"
    if isinstance(error, anthropic.AuthenticationError):
        return "auth_error"  # a bad key: retrying changes nothing
    if isinstance(error, anthropic.APIStatusError):
        if error.status_code >= 500:
            return "server_error"
        return f"api_error:{error.status_code}"
    return f"api_error:{type(error).__name__}"


# --------------------------------------------------------------------------
# Building the request
# --------------------------------------------------------------------------


def build_user_message(payload: Payload) -> str:
    """Everything that changes per request goes here, below the cache point."""
    sections = [payload.skeleton_text]

    if payload.windows:
        sections.append("\n## CODE AROUND EACH FINDING\n")
        sections.extend(window.text for window in payload.windows)

    if payload.findings:
        sections.append("\n## WHAT THE DETECTORS FOUND\n")
        for finding in payload.findings:
            sections.append(
                f"[{finding.severity}] {finding.path}:{finding.line} "
                f"({finding.category}) {finding.message}"
            )

    if payload.dropped_windows:
        sections.append(
            f"\n[{payload.dropped_windows} lower-severity windows were omitted "
            "to stay within budget. Do not comment on code you were not shown.]"
        )

    return "\n".join(sections)


def _system_blocks() -> list[dict]:
    """The system prompt, marked cacheable.

    It is fixed, so nothing volatile may appear above this block — a single
    changing byte in the prefix means the cache never hits.

    **Measured caveat:** this prompt is about 1,660 characters, roughly 415
    tokens, and the minimum cacheable prefix on Opus 5 is 512 tokens. Below
    that the marker is silently ignored — no error, just
    `cache_creation_input_tokens: 0`. The marker is kept because it costs
    nothing and starts working the moment the prompt grows past the
    threshold.

    The larger prize is elsewhere: on a repeat analysis of the same project
    the SKELETON is stable and roughly 4,800 tokens. A cache breakpoint
    after it in the user turn would make re-runs far cheaper. Worth doing
    once repeat analysis exists — measure `usage.cache_read_input_tokens`
    before and after rather than assuming.
    """
    return [
        {
            "type": "text",
            "text": SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }
    ]


# --------------------------------------------------------------------------
# Verification: the model may only talk about code it was shown
# --------------------------------------------------------------------------


def verify(
    report: ClaudeReport,
    contents: dict[str, str],
    skeleton: ProjectSkeleton | None = None,
) -> tuple[ClaudeReport, int]:
    """Drop every claim that cannot be checked against the real code.

    A model will confidently describe a file that does not exist or cite a
    line past the end of one. Checking costs nothing and turns a plausible
    invention into a dropped row.
    """
    line_counts = {path: len(content.splitlines()) for path, content in contents.items()}
    dropped = 0

    def real_location(path: str, line: int) -> bool:
        return path in line_counts and 1 <= line <= max(line_counts[path], 1)

    steps = []
    for step in report.reading_order:
        if step.path in contents:
            steps.append(step)
        else:
            dropped += 1

    symbols = []
    for symbol in report.symbols_to_clarify:
        # The name must exist in that file: a renamed symbol the model
        # invented would otherwise be presented as fact.
        if real_location(symbol.path, symbol.line) and symbol.current_name in contents.get(
            symbol.path, ""
        ):
            symbols.append(symbol)
        else:
            dropped += 1

    explained = []
    for finding in report.explained_findings:
        if real_location(finding.path, finding.line):
            explained.append(finding)
        else:
            dropped += 1

    verified = report.model_copy(
        update={
            "reading_order": steps,
            "symbols_to_clarify": symbols,
            "explained_findings": explained,
        }
    )
    return verified, dropped


# --------------------------------------------------------------------------
# The call
# --------------------------------------------------------------------------


def _build_client():
    """Return an SDK client, or None when there is no key to use.

    Imported lazily so the whole backend still runs — and every test still
    passes — on a machine where the SDK is not installed.
    """
    import settings

    if not settings.has_api_key():
        return None
    try:
        import anthropic
    except ImportError:
        return None
    return anthropic.Anthropic(timeout=REQUEST_TIMEOUT_SECONDS)


def analyse(
    payload: Payload,
    contents: dict[str, str],
    skeleton: ProjectSkeleton | None = None,
    client=None,
) -> ClaudeResult:
    """Ask Claude for meaning. Never raises.

    Pass `client` to use an injected one; otherwise a real client is built
    from the environment. Every failure path returns a ClaudeResult saying
    what went wrong, so the caller can show the deterministic report and say
    the explanations are missing.
    """
    client = client or _build_client()
    if client is None:
        return ClaudeResult(None, False, "no_api_key")

    user_message = build_user_message(payload)
    messages = [{"role": "user", "content": user_message}]

    try:
        # count_tokens is the authority. The character estimate in context.py
        # is a pre-filter; this is the number the bill is based on.
        counted = client.messages.count_tokens(
            model=MODEL, system=_system_blocks(), messages=messages
        )
        if counted.input_tokens > MAX_INPUT_TOKENS:
            return ClaudeResult(None, False, "budget_exceeded")

        response = client.messages.parse(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=_system_blocks(),
            messages=messages,
            output_format=ClaudeReport,
        )
    except Exception as error:  # noqa: BLE001 - any failure degrades, never raises
        return ClaudeResult(None, False, classify_error(error))

    # Safety classifiers can decline a request. This tool exists to ingest
    # SQL injection, eval and hardcoded secrets, so that is a realistic
    # outcome here — and reading content[0] before checking would crash.
    if getattr(response, "stop_reason", None) == "refusal":
        return ClaudeResult(None, False, "refusal")

    report = getattr(response, "parsed_output", None)
    if report is None:
        return ClaudeResult(None, False, "unparsable_response")

    verified, dropped = verify(report, contents, skeleton)

    usage = getattr(response, "usage", None)
    return ClaudeResult(
        report=verified,
        available=True,
        input_tokens=getattr(usage, "input_tokens", 0) if usage else 0,
        output_tokens=getattr(usage, "output_tokens", 0) if usage else 0,
        cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) if usage else 0,
        dropped_claims=dropped,
    )
