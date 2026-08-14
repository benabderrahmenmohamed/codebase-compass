"""Tests of the Claude layer — all offline, with a recorded response.

No API key is needed and no request leaves the machine. Every path through
this layer, including all four failure modes, is verified before a key ever
exists.
"""

import builtins
from types import SimpleNamespace

import anthropic
import httpx
import pytest

from analysis import claude_client, context, findings, scoring, skeleton
from schemas import ClarifiedSymbol, ClaudeReport, ExplainedFinding, ReadingStep

CONTENTS = {
    "app/main.py": "\n".join(f"line {n}" for n in range(1, 31)) + "\n",
    "app/models.py": "class Order:\n    pass\n",
}


def a_report(**overrides) -> ClaudeReport:
    defaults = dict(
        overview="A small ordering service.",
        reading_order=[ReadingStep(path="app/models.py", why="Everything imports it.")],
        symbols_to_clarify=[
            ClarifiedSymbol(
                path="app/main.py",
                line=5,
                current_name="line",
                actually_holds="The token expiry date, in UTC.",
                suggested_name="expiry_date",
            )
        ],
        explained_findings=[
            ExplainedFinding(
                path="app/main.py",
                line=7,
                why_it_matters="It can be exploited.",
                how_to_fix="Use a parameterised query.",
                what_you_learn="Data is not instructions.",
            )
        ],
        questions_for_the_team=["Why two order tables?"],
    )
    defaults.update(overrides)
    return ClaudeReport(**defaults)


class FakeClient:
    """Stands in for the SDK. Records what it was asked, returns a canned reply."""

    def __init__(self, report=None, input_tokens=1000, stop_reason="end_turn", raises=None):
        self._report = report if report is not None else a_report()
        self._input_tokens = input_tokens
        self._stop_reason = stop_reason
        self._raises = raises
        self.parse_calls = []
        self.messages = SimpleNamespace(
            count_tokens=self._count_tokens, parse=self._parse
        )

    def _count_tokens(self, **kwargs):
        return SimpleNamespace(input_tokens=self._input_tokens)

    def _parse(self, **kwargs):
        if self._raises:
            raise self._raises
        self.parse_calls.append(kwargs)
        return SimpleNamespace(
            parsed_output=self._report,
            stop_reason=self._stop_reason,
            usage=SimpleNamespace(
                input_tokens=self._input_tokens,
                output_tokens=400,
                cache_read_input_tokens=900,
            ),
        )


def a_payload() -> context.Payload:
    project_findings = [
        findings.Finding(
            path="app/main.py",
            line=7,
            severity="critical",
            category="security",
            message="SQL injection.",
            suggestion="Parameterise.",
            source="semgrep",
            penalty=10,
        )
    ]
    return context.build_payload(
        CONTENTS, skeleton.build(CONTENTS), project_findings
    )


def run(client) -> claude_client.ClaudeResult:
    return claude_client.analyse(a_payload(), CONTENTS, client=client)


# ---------------------------------------------------------------- happy path


def test_a_valid_response_is_returned_as_a_validated_model():
    result = run(FakeClient())

    assert result.available
    assert isinstance(result.report, ClaudeReport)
    assert result.report.overview.startswith("A small")


def test_usage_is_reported():
    result = run(FakeClient())

    assert result.input_tokens == 1000
    assert result.output_tokens == 400
    assert result.cache_read_tokens == 900
    assert result.used_cache


# ------------------------------------------------------------ the request


def test_the_system_prompt_is_marked_cacheable():
    client = FakeClient()
    run(client)

    system = client.parse_calls[0]["system"]
    assert system[0]["cache_control"] == {"type": "ephemeral"}


def test_nothing_volatile_sits_above_the_cache_breakpoint():
    """A changing system prompt means the cache never hits."""
    first, second = FakeClient(), FakeClient()
    run(first)
    run(second)

    assert first.parse_calls[0]["system"] == second.parse_calls[0]["system"]


def test_the_model_is_asked_with_structured_output():
    client = FakeClient()
    run(client)

    assert client.parse_calls[0]["output_format"] is ClaudeReport


def test_the_user_message_carries_the_map_the_windows_and_the_findings():
    client = FakeClient()
    run(client)

    message = client.parse_calls[0]["messages"][0]["content"]
    assert "FILES:" in message
    assert "app/main.py lines" in message
    assert "SQL injection." in message


def test_the_prompt_tells_the_model_not_to_discuss_unseen_code():
    assert "Never invent" in claude_client.SYSTEM_PROMPT
    assert "must be one that was shown to you" in claude_client.SYSTEM_PROMPT


# ------------------------------------------------------------- degradation


@pytest.mark.parametrize("absent", ["deleted", "empty"], ids=["deleted", "empty"])
def test_no_api_key_degrades_instead_of_failing(monkeypatch, absent):
    """Both shapes of "no key" must behave the same.

    An empty ANTHROPIC_API_KEY is not a key. Treating "" as present would
    send an unauthenticated request and get a 401 instead of degrading
    cleanly — and it is what the test suite itself sets, to stop a developer's
    .env from being loaded mid-run.
    """
    if absent == "deleted":
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    else:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "")

    result = claude_client.analyse(a_payload(), CONTENTS)

    assert result.available is False
    assert result.reason == "no_api_key"
    assert result.report is None


def test_a_refusal_is_detected_before_the_content_is_read():
    """This tool ingests SQL injection and eval on purpose, so a safety
    refusal is a realistic outcome, not a hypothetical one."""
    result = run(FakeClient(stop_reason="refusal"))

    assert result.available is False
    assert result.reason == "refusal"


def test_an_unknown_error_degrades():
    result = run(FakeClient(raises=RuntimeError("something odd")))

    assert result.available is False
    assert result.reason == "api_error:RuntimeError"


# --- each SDK failure classified, and marked retryable or not --------------

REQUEST = httpx.Request("POST", "https://api.anthropic.com/v1/messages")


def sdk_errors():
    return [
        (anthropic.APITimeoutError(request=REQUEST), "timeout", True),
        (
            anthropic.RateLimitError(
                "slow down", response=httpx.Response(429, request=REQUEST), body=None
            ),
            "rate_limited",
            True,
        ),
        (
            anthropic.APIConnectionError(message="unreachable", request=REQUEST),
            "network_error",
            True,
        ),
        (
            anthropic.InternalServerError(
                "boom", response=httpx.Response(503, request=REQUEST), body=None
            ),
            "server_error",
            True,
        ),
        (
            anthropic.AuthenticationError(
                "bad key", response=httpx.Response(401, request=REQUEST), body=None
            ),
            "auth_error",
            False,
        ),
        (
            anthropic.BadRequestError(
                "malformed", response=httpx.Response(400, request=REQUEST), body=None
            ),
            "api_error:400",
            False,
        ),
    ]


@pytest.mark.parametrize(
    "error,expected_reason,expected_retryable",
    sdk_errors(),
    ids=[reason for _, reason, _ in sdk_errors()],
)
def test_every_sdk_failure_is_classified(error, expected_reason, expected_retryable):
    result = run(FakeClient(raises=error))

    assert result.available is False
    assert result.reason == expected_reason
    assert result.is_retryable is expected_retryable


def test_a_timeout_is_not_mistaken_for_a_generic_network_error():
    """APITimeoutError subclasses APIConnectionError, so order matters."""
    timeout = run(FakeClient(raises=anthropic.APITimeoutError(request=REQUEST)))
    connection = run(
        FakeClient(raises=anthropic.APIConnectionError(message="x", request=REQUEST))
    )

    assert timeout.reason == "timeout"
    assert connection.reason == "network_error"


def test_a_refusal_is_never_retried():
    """The same request would be refused again: retrying only costs money."""
    assert run(FakeClient(stop_reason="refusal")).is_retryable is False


def test_an_over_budget_payload_is_never_retried():
    client = FakeClient(input_tokens=claude_client.MAX_INPUT_TOKENS + 1)

    assert run(client).is_retryable is False


def test_a_failure_while_counting_tokens_also_degrades():
    """count_tokens is a network call too, and fails the same ways."""

    class CountFails(FakeClient):
        def _count_tokens(self, **kwargs):
            raise anthropic.APITimeoutError(request=REQUEST)

    result = run(CountFails())

    assert result.reason == "timeout"
    assert result.is_retryable


def test_a_missing_sdk_degrades_rather_than_crashing(monkeypatch):
    """The backend must still run where the SDK was never installed."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-used")
    real_import = builtins.__import__

    def no_anthropic(name, *args, **kwargs):
        if name == "anthropic":
            raise ImportError("no module named anthropic")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_anthropic)

    result = claude_client.analyse(a_payload(), CONTENTS)

    assert result.available is False
    assert result.reason == "no_api_key"


def test_a_response_without_usage_does_not_crash():
    class NoUsage(FakeClient):
        def _parse(self, **kwargs):
            self.parse_calls.append(kwargs)
            return SimpleNamespace(
                parsed_output=a_report(), stop_reason="end_turn", usage=None
            )

    result = run(NoUsage())

    assert result.available
    assert result.input_tokens == 0
    assert result.used_cache is False


def test_an_over_budget_payload_is_never_sent():
    client = FakeClient(input_tokens=claude_client.MAX_INPUT_TOKENS + 1)

    result = run(client)

    assert result.reason == "budget_exceeded"
    assert client.parse_calls == []  # nothing was sent, nothing was billed


def test_an_unparsable_response_degrades():
    class Broken(FakeClient):
        def _parse(self, **kwargs):
            return SimpleNamespace(parsed_output=None, stop_reason="end_turn", usage=None)

    result = run(Broken())

    assert result.reason == "unparsable_response"


# ------------------------------------------------------------ verification


def test_a_claim_about_a_file_that_does_not_exist_is_dropped():
    report = a_report(
        reading_order=[ReadingStep(path="app/ghost.py", why="Invented.")]
    )

    result = run(FakeClient(report=report))

    assert result.report.reading_order == []
    assert result.dropped_claims == 1


def test_a_line_past_the_end_of_a_file_is_dropped():
    """The line-34-in-a-5-line-file bug, now guarding the model too."""
    report = a_report(
        explained_findings=[
            ExplainedFinding(
                path="app/models.py",  # 2 lines long
                line=340,
                why_it_matters="w",
                how_to_fix="h",
                what_you_learn="l",
            )
        ]
    )

    result = run(FakeClient(report=report))

    assert result.report.explained_findings == []
    assert result.dropped_claims == 1


def test_a_symbol_that_does_not_appear_in_the_file_is_dropped():
    report = a_report(
        symbols_to_clarify=[
            ClarifiedSymbol(
                path="app/main.py",
                line=5,
                current_name="never_written_anywhere",
                actually_holds="x",
                suggested_name="y",
            )
        ]
    )

    result = run(FakeClient(report=report))

    assert result.report.symbols_to_clarify == []
    assert result.dropped_claims == 1


def test_valid_claims_survive_verification():
    result = run(FakeClient())

    assert len(result.report.symbols_to_clarify) == 1
    assert len(result.report.explained_findings) == 1
    assert len(result.report.reading_order) == 1
    assert result.dropped_claims == 0


def test_prose_is_never_dropped():
    """Only checkable claims are verified; the overview is judgement."""
    report = a_report(overview="A long narrative about the architecture.")

    result = run(FakeClient(report=report))

    assert result.report.overview == "A long narrative about the architecture."
    assert result.report.questions_for_the_team == ["Why two order tables?"]


@pytest.mark.parametrize("line", [0, -3])
def test_an_impossible_line_number_is_refused_by_the_schema(line):
    """ge=1 on the model means a nonsense line never reaches verification."""
    with pytest.raises(ValueError):
        ExplainedFinding(
            path="app/main.py",
            line=line,
            why_it_matters="w",
            how_to_fix="h",
            what_you_learn="l",
        )


# ================================================================
# The promise: whatever Claude does, the offline report survives
# ================================================================

VULNERABLE_PROJECT = {
    "app/main.py": (
        "import hashlib\n\n"
        'PASSWORD = "admin123"\n\n\n'
        "def get_user(connection, user_id):\n"
        '    query = "SELECT * FROM users WHERE id = " + user_id\n'
        "    return connection.execute(query)\n\n\n"
        "def digest(text):\n"
        "    return hashlib.md5(text.encode()).hexdigest()\n"
    ),
    "app/models.py": "class Order:\n    pass\n",
}


def deterministic_part():
    """Everything that does not need the network."""
    collection = findings.collect(VULNERABLE_PROJECT)
    score = scoring.score_project(
        VULNERABLE_PROJECT, collection.findings, collection.semgrep_available
    )
    payload = context.build_payload(
        VULNERABLE_PROJECT, skeleton.build(VULNERABLE_PROJECT), collection.findings
    )
    return collection, score, payload


@pytest.mark.parametrize(
    "client",
    [
        FakeClient(stop_reason="refusal"),
        FakeClient(raises=anthropic.APITimeoutError(request=REQUEST)),
        FakeClient(
            raises=anthropic.RateLimitError(
                "slow", response=httpx.Response(429, request=REQUEST), body=None
            )
        ),
        FakeClient(input_tokens=claude_client.MAX_INPUT_TOKENS + 1),
        None,  # no API key at all
    ],
    ids=["refusal", "timeout", "rate_limited", "budget_exceeded", "no_key"],
)
def test_the_deterministic_report_survives_every_claude_failure(client, monkeypatch):
    """A report without explanations is a smaller report, not a broken one.

    Findings, scores and the grade are all produced offline. The LLM adds
    meaning on top; it is never the thing that makes a report exist.
    """
    if client is None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    collection, score, payload = deterministic_part()
    result = claude_client.analyse(payload, VULNERABLE_PROJECT, client=client)

    # Claude gave nothing...
    assert result.available is False
    assert result.report is None

    # ...and the report is still complete and correct.
    assert collection.findings
    assert score.scores["security"].score <= 5  # the injection was still caught
    assert score.grade in ("D", "E")
    assert score.total > 0
    assert payload.windows  # the evidence is still assembled


def test_a_claude_failure_is_distinguishable_from_a_clean_bill_of_health():
    """The report must never imply the explanations were simply unnecessary."""
    _, _, payload = deterministic_part()

    result = claude_client.analyse(
        payload, VULNERABLE_PROJECT, client=FakeClient(stop_reason="refusal")
    )

    assert result.reason == "refusal"  # a stated cause, not silence
    assert result.available is False
