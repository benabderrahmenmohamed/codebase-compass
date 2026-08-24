"""The Pydantic models: the API contract.

This file describes the SHAPE of the data exchanged. FastAPI uses it to
validate what comes in, filter what goes out, and generate the /docs page.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Severity(str, Enum):
    """How serious a finding is. Only these 4 values are accepted."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Issue(BaseModel):
    """One specific problem, tied to a line of the submitted code."""

    line: int = Field(ge=1, description="Line number concerned (starts at 1)")
    severity: Severity = Field(description="How serious the problem is")
    message: str = Field(description="What is wrong")
    suggestion: str = Field(description="How to fix it")


class Scores(BaseModel):
    """The 5 categories, each scored out of 20 (total = 100)."""

    security: int = Field(ge=0, le=20)
    readability: int = Field(ge=0, le=20)
    maintainability: int = Field(ge=0, le=20)
    performance: int = Field(ge=0, le=20)
    best_practices: int = Field(ge=0, le=20)


class AnalysisRequest(BaseModel):
    """What the client SENDS in the body of POST /analyses."""

    # This example pre-fills the "Try it out" button on the /docs page.
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "code": "def get_user(user_id):\n"
                    '    query = "SELECT * FROM users WHERE id = " + user_id\n'
                    "    return db.execute(query)\n",
                    "language": "python",
                }
            ]
        }
    )

    code: str = Field(
        min_length=1,
        max_length=50_000,
        description="The source code to analyse",
    )
    language: str | None = Field(
        default=None,
        description="Language of the code. Optional: detected automatically if absent.",
    )

    @field_validator("code")
    @classmethod
    def code_must_not_be_blank(cls, value: str) -> str:
        # min_length=1 rejects "" but lets "   " through: we complete it here.
        if not value.strip():
            raise ValueError("code cannot be empty or only whitespace")
        return value


class AnalysisResponse(BaseModel):
    """What the API RETURNS: the complete analysis report."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "id": "8f1c2d3e-4b5a-6c7d-8e9f-0a1b2c3d4e5f",
                    "language": "python",
                    "scores": {
                        "security": 12,
                        "readability": 16,
                        "maintainability": 14,
                        "performance": 17,
                        "best_practices": 15,
                    },
                    "total_score": 74,
                    "issues": [
                        {
                            "line": 12,
                            "severity": "critical",
                            "message": "SQL query assembled by concatenation: "
                            "SQL injection is possible.",
                            "suggestion": "Use a parameterised query.",
                        }
                    ],
                    "created_at": "2026-08-11T09:30:00Z",
                }
            ]
        }
    )

    id: str = Field(description="Unique identifier of the analysis (UUID)")
    language: str = Field(description="Language used for the analysis")
    scores: Scores = Field(description="The 5 scores out of 20")
    total_score: int = Field(
        ge=0,
        le=100,
        description="Sum of the 5 categories, computed by the server",
    )
    issues: list[Issue] = Field(description="The problems found")
    created_at: datetime = Field(description="Creation date, in UTC")


# ==========================================================================
# PROJECT mode: several files submitted together
# ==========================================================================


class ProjectFile(BaseModel):
    """One file of a submitted project.

    This model only checks the SHAPE of the path (non-empty, reasonable
    length, no null byte). Policy decisions — allowed extension, ignored
    folder, limits — are taken elsewhere: a Pydantic model can only accept or
    refuse everything, whereas we need to say "I kept 8 files out of 12".
    """

    path: str = Field(
        min_length=1,
        max_length=500,
        description="Relative path inside the project, e.g. app/routes/orders.py",
    )
    content: str = Field(description="The file contents, as text")

    @field_validator("path")
    @classmethod
    def path_without_null_byte(cls, value: str) -> str:
        # A null byte in a path is a known trick: everything after \x00 is
        # ignored by some system libraries but not by checks written in
        # Python. Two components reading the same path differently is a bug.
        if "\x00" in value:
            raise ValueError("path contains a null byte")
        return value


class ProjectSubmission(BaseModel):
    """What the client SENDS in the body of POST /projects.

    A project arrives one of two ways: `files`, uploaded from a folder the
    user picked, or `repo`, a public GitHub repository we fetch ourselves.
    Exactly one — see `exactly_one_source` below for why "both" is an
    error rather than a preference.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "name": "order-service",
                    "files": [
                        {
                            "path": "app/main.py",
                            "content": "from fastapi import FastAPI\n\napp = FastAPI()\n",
                        },
                        {
                            "path": "app/models.py",
                            "content": "class Order:\n    pass\n",
                        },
                    ],
                },
                {"repo": "https://github.com/benabderrahmenmohamed/codebase-compass"},
            ]
        }
    )

    name: str | None = Field(
        default=None,
        max_length=100,
        description="Project name. Optional.",
    )
    files: list[ProjectFile] | None = Field(
        default=None,
        min_length=1,
        description="The project files, when uploading a folder.",
    )
    repo: str | None = Field(
        default=None,
        max_length=300,
        description=(
            "A public GitHub repository: a browser URL, an SSH remote, or "
            "owner/repo. Any other host is refused."
        ),
    )

    @model_validator(mode="after")
    def exactly_one_source(self):
        """Refuse a submission that names no source, or two.

        Neither is obvious. Both is the interesting case, and it is refused
        rather than resolved.

        Preferring one silently would hand the user a report about code they
        did not think they submitted — they would read a grade for a GitHub
        repository while looking at the folder they had picked, and nothing
        on the page would say so. That is the same failure the whole project
        is built to avoid: an answer that looks complete while quietly
        describing something else.

        The interface prevents this from arising at all by clearing one
        field when the other is used. This check is what protects the API
        from a caller that has no such interface.
        """
        if self.files and self.repo:
            raise ValueError(
                "Send either 'files' or 'repo', not both. "
                "Two sources would produce one report, and it could only "
                "describe one of them."
            )
        if not self.files and not self.repo:
            raise ValueError("Send either 'files' (a picked folder) or 'repo'.")
        return self


class AcceptedFile(BaseModel):
    """A file kept for analysis."""

    path: str = Field(description="Normalised relative path")
    hash: str = Field(description="SHA-256 fingerprint of the content")
    chars: int = Field(ge=0, description="Number of characters")


class SkippedFile(BaseModel):
    """A file left out, with the reason.

    Skipping is not refusing: the submission stays valid. A real project
    contains READMEs and images, and the user must see what was not analysed
    rather than having to guess.
    """

    path: str
    reason: str = Field(
        description=(
            "suspicious_path | ignored_folder | unsupported_extension | duplicate"
        )
    )


class ProjectResponse(BaseModel):
    """What the API returns after a project submission."""

    project_id: str = Field(description="Unique identifier of the project (UUID)")
    name: str | None = Field(description="Name supplied by the client")
    source: str = Field(
        default="upload",
        description="upload | github — where the files came from",
    )
    repo_url: str | None = Field(
        default=None,
        description="The repository analysed, when source is github",
    )
    truncated: bool = Field(
        default=False,
        description=(
            "True when the repository was too large to list in full, so "
            "files exist that were never even seen"
        ),
    )
    accepted_files: list[AcceptedFile] = Field(description="Files kept")
    skipped: list[SkippedFile] = Field(description="Files left out, and why")
    total_chars: int = Field(ge=0, description="Total size kept")
    created_at: datetime = Field(description="Creation date, in UTC")


# ==========================================================================
# What Claude returns
#
# These are the SAME kind of Pydantic models that validate the API's input.
# The SDK validates the model's answer against them, so there is no
# json.loads, no regex, and no "please reply only in JSON" in the prompt.
# One concept, both ends of the system.
# ==========================================================================


class ClarifiedSymbol(BaseModel):
    """A name translated into what it actually holds.

    The flagship output. A linter can say `x` is a bad name; only something
    that reads the surrounding code can say `x` holds a token expiry date.
    """

    path: str = Field(description="File the symbol lives in")
    line: int = Field(ge=1, description="Line where it is defined")
    current_name: str = Field(description="The name as written today")
    actually_holds: str = Field(
        description="What the value really contains, in one sentence"
    )
    suggested_name: str = Field(description="A name that would say that")


class ExplainedFinding(BaseModel):
    """A detector finding, explained for someone who has not seen this code."""

    path: str
    line: int = Field(ge=1)
    why_it_matters: str = Field(description="The consequence, concretely")
    how_to_fix: str = Field(description="The change to make")
    what_you_learn: str = Field(description="The idea this teaches")
    likely_false_positive: bool = Field(
        default=False,
        description="True if the rule fired but the code is actually fine",
    )


class ReadingStep(BaseModel):
    """One step of a suggested reading order."""

    path: str
    why: str = Field(description="Why read this one at this point")


class ClaudeReport(BaseModel):
    """Everything the model is asked to produce, in one validated object."""

    overview: str = Field(description="What this project is, in a short paragraph")
    reading_order: list[ReadingStep] = Field(default_factory=list)
    symbols_to_clarify: list[ClarifiedSymbol] = Field(default_factory=list)
    explained_findings: list[ExplainedFinding] = Field(default_factory=list)
    questions_for_the_team: list[str] = Field(
        default_factory=list,
        description="What the analysis raises but cannot settle on its own",
    )


# ==========================================================================
# The full project report
# ==========================================================================


class CategoryScoreOut(BaseModel):
    """One category's score, with how it was reached and how far it looked."""

    score: int = Field(ge=0, le=20)
    coverage: str = Field(
        description="evaluated | partially_evaluated | not_evaluated — "
        "a score of 20 is not a claim of coverage"
    )
    finding_count: int = Field(ge=0)
    method: str = Field(description="worst_finding | density | none")
    density: float | None = Field(
        default=None, description="Weighted findings per 100 lines"
    )


class FindingOut(BaseModel):
    """One problem found by a detector."""

    path: str
    line: int = Field(ge=1)
    severity: Severity
    category: str
    message: str
    suggestion: str
    source: str = Field(description="semgrep | metrics | naming | clones")
    symbol: str | None = None


class FileReportOut(BaseModel):
    """One file's place in the project and its own health."""

    path: str
    language: str
    lines: int = Field(ge=0)
    imports: list[str]
    imported_by: list[str]
    is_entry_point: bool
    parse_error: str | None
    symbol_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    total_score: int | None = Field(default=None, ge=0, le=100)
    grade: str | None = None
    top_findings: list[FindingOut]


class ProjectAnalysisResponse(BaseModel):
    """The whole report: health, map, findings, and what could not be done."""

    project_id: str
    created_at: datetime

    scores: dict[str, CategoryScoreOut]
    total_score: int = Field(ge=0, le=100)
    grade: str | None
    worst_file: str | None
    best_file: str | None

    entry_points: list[str]
    external_dependencies: list[str]
    reading_order: list[str]
    files: list[FileReportOut]

    findings: list[FindingOut]
    findings_dropped: int = Field(
        ge=0, description="Findings beyond the cap: counted, never hidden"
    )

    analysis_complete: bool = Field(
        description="False when any layer could not run in full"
    )
    semgrep_available: bool
    semgrep_reason: str | None
    context_windows_dropped: int = Field(ge=0)
    findings_not_explained: int = Field(
        default=0,
        ge=0,
        description=(
            "Findings ranked below the explanation cap. They are listed "
            "in full under `findings`; the model was not asked to write "
            "about them, because output is what costs time and money."
        ),
    )
    estimated_tokens: int = Field(ge=0)

    llm_used: bool
    llm_reason: str | None = Field(
        description="Why the explanations are missing, when they are"
    )
    llm_retryable: bool = Field(
        default=False, description="Whether asking again could succeed"
    )
    llm_dropped_claims: int = Field(
        default=0,
        ge=0,
        description="Model claims discarded because they did not match the code",
    )
    llm_input_tokens: int = Field(default=0, ge=0)
    llm_output_tokens: int = Field(default=0, ge=0)
    llm_cache_read_tokens: int = Field(
        default=0, ge=0, description="Tokens served from cache, at 0.1x price"
    )
    llm_cost_usd: float = Field(
        default=0.0,
        ge=0,
        description="Estimated cost of this run. Output dominates: it was 93% "
        "of the bill in measurement, so cost tracks how much the model had "
        "to explain, not how much code was sent.",
    )
    explanations: ClaudeReport | None = None


class ErrorResponse(BaseModel):
    """The shape of FastAPI's error responses (404, 413, ...)."""

    model_config = ConfigDict(
        json_schema_extra={"examples": [{"detail": "Analysis not found"}]}
    )

    detail: str = Field(description="Message explaining the error")
