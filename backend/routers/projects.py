"""Endpoints for the "projects" domain.

A project is a set of files submitted together. This endpoint does the
reception ONLY: filter, bound, store. Analysis comes later.
"""

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status

import notifications
import permissions
import settings
import storage
from analysis import github_source, ingestion, report
from permissions import User
from routers import security
from schemas import (
    ErrorResponse,
    ProjectAnalysisResponse,
    ProjectResponse,
    ProjectSubmission,
)

router = APIRouter(prefix="/projects", tags=["Projects"])

# The fetch layer knows nothing about HTTP: it returns a stable reason
# string. This is the one place those become status codes — the same
# arrangement as ingestion.LimitExceeded becoming a 413.
_FETCH_STATUS = {
    "invalid_reference": status.HTTP_422_UNPROCESSABLE_CONTENT,
    "not_found": status.HTTP_404_NOT_FOUND,
    "ref_not_found": status.HTTP_404_NOT_FOUND,
    "empty_repository": status.HTTP_422_UNPROCESSABLE_CONTENT,
    "no_analysable_files": status.HTTP_422_UNPROCESSABLE_CONTENT,
    "rate_limited": status.HTTP_429_TOO_MANY_REQUESTS,
    "forbidden": status.HTTP_403_FORBIDDEN,
    "unavailable_for_legal_reasons": 451,
    "timeout": status.HTTP_504_GATEWAY_TIMEOUT,
}

_FETCH_MESSAGE = {
    "invalid_reference": (
        "That is not a GitHub repository. Paste a github.com URL or "
        "owner/repo — other hosts are not fetched."
    ),
    "not_found": (
        "No such public repository. GitHub returns the same answer for a "
        "repository that does not exist and one that is private, so it may "
        "be either."
    ),
    "ref_not_found": "The repository exists, but that branch or tag does not.",
    "empty_repository": "That repository has no commits.",
    "no_analysable_files": (
        "The repository was read, but it holds no file in a language this "
        "tool analyses."
    ),
    "no_files_readable": "The file list was read, but none of the files could be fetched.",
    "rate_limited": (
        "GitHub's rate limit was reached. Setting GITHUB_TOKEN raises it "
        "from 60 requests an hour to 5000."
    ),
    "forbidden": "GitHub refused the request.",
    "unavailable_for_legal_reasons": "GitHub has made that repository unavailable.",
    "timeout": "GitHub did not answer in time.",
    "network_error": "GitHub could not be reached.",
}


def _fetch_from_github(reference: str) -> github_source.GitHubResult:
    """Fetch a repository, or raise the matching HTTP error."""
    result = github_source.fetch_repo(reference, token=settings.github_token())
    if result.available:
        return result

    reason = result.reason or "network_error"
    detail = _FETCH_MESSAGE.get(reason, f"The repository could not be read ({reason}).")
    if reason in github_source.RETRYABLE_REASONS:
        detail += " Trying again may work."

    raise HTTPException(
        status_code=_FETCH_STATUS.get(reason, status.HTTP_502_BAD_GATEWAY),
        detail=detail,
    )


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=ProjectResponse,
    summary="Submit a project to analyse",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "The repository does not exist, or is private",
        },
        status.HTTP_413_CONTENT_TOO_LARGE: {
            "model": ErrorResponse,
            "description": "A limit was exceeded (detailed message)",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorResponse,
            "description": (
                "No source, both sources, an unusable reference, or nothing "
                "analysable in the repository"
            ),
        },
        status.HTTP_429_TOO_MANY_REQUESTS: {
            "model": ErrorResponse,
            "description": "GitHub's rate limit was reached",
        },
        status.HTTP_502_BAD_GATEWAY: {
            "model": ErrorResponse,
            "description": "GitHub could not be reached",
        },
    },
)
def create_project(payload: ProjectSubmission, user: User = security.CurrentUser):
    """Receive a project, skip what is not analysable, store the rest.

    The files arrive either uploaded from a picked folder or fetched from a
    public GitHub repository. Once they are here the two are identical:
    ingestion re-validates every path regardless of origin, because a path
    from GitHub is no more trustworthy than a path from a browser.

    A non-conforming file is SKIPPED (and listed in `skipped`); only an
    exceeded limit refuses the whole submission, with a 413.
    """
    security.require(user, permissions.SUBMIT_PROJECT)

    source = "upload"
    repo_url = None
    truncated = False
    pre_skipped: list = []

    if payload.repo:
        fetched = _fetch_from_github(payload.repo)
        files = fetched.files
        source = "github"
        repo_url = fetched.ref.url if fetched.ref else None
        truncated = fetched.truncated
        # What the fetcher already rejected, on names and sizes, before it
        # downloaded anything. Merged with ingestion's own skips so the user
        # sees one list rather than two.
        pre_skipped = [file._asdict() for file in fetched.skipped]
        name = payload.name or (fetched.ref.slug if fetched.ref else None)
    else:
        files = payload.files
        name = payload.name

    try:
        result = ingestion.prepare(files)
    except ingestion.LimitExceeded as exceeded:
        # The ingestion layer knows nothing about HTTP: this is where its
        # domain exception is translated into a status code.
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=str(exceeded),
        ) from exceeded

    project = {
        "project_id": str(uuid4()),
        "name": name,
        "owner": user.name,
        "source": source,
        "repo_url": repo_url,
        "truncated": truncated,
        "accepted_files": [file._asdict() for file in result.accepted],
        "skipped": pre_skipped + [file._asdict() for file in result.skipped],
        "total_chars": result.total_chars,
        "created_at": datetime.now(timezone.utc),
        # Contents are kept separately: they never appear in the response
        # (response_model filters them out), but the next layers need them.
        "_contents": {
            ingestion.normalise(f.path): f.content
            for f in files
            if not ingestion.is_suspicious_path(ingestion.normalise(f.path))
        },
    }

    storage.save_project(project)
    return project


@router.get(
    "",
    response_model=list[ProjectResponse],
    summary="List every project",
)
def list_projects(user: User = security.CurrentUser):
    """Return the projects this user may see, oldest first."""
    return permissions.visible_to(user, storage.get_all_projects())


@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
    summary="Fetch one project by id",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "No project carries this id",
        }
    },
)
def get_project(project_id: str, user: User = security.CurrentUser):
    """Return one project, or 404 if the id is unknown or not yours."""
    project = storage.get_project_by_id(project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    security.require_readable(user, project, "Project")
    return project


@router.post(
    "/{project_id}/analysis",
    response_model=ProjectAnalysisResponse,
    summary="Analyse a stored project",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "No project carries this id",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorResponse,
            "description": "The project has no analysable file",
        },
    },
)
def analyse_project(
    project_id: str, use_llm: bool = True, user: User = security.CurrentUser
):
    """Run the full analysis and return the report.

    Submission and analysis are separate calls on purpose: ingestion is
    instant, so the user sees "12 files accepted, 3 skipped" immediately
    instead of staring at a blank screen while Semgrep and the model work.

    `use_llm=false` returns the deterministic report only — no API call, no
    cost. Everything except the explanations is identical.
    """
    project = storage.get_project_by_id(project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    security.require_readable(user, project, "Project")

    # A guest asking for the AI review is not an error: the deterministic
    # report is produced and says the explanations are missing, exactly as
    # it does when there is no API key. This is the cost control — an
    # anonymous visitor cannot spend the owner's Anthropic credit — and it
    # lives in the permission matrix rather than in a rate limiter.
    use_llm = permissions.llm_allowed(user, use_llm)

    contents = {
        file["path"]: project["_contents"][file["path"]]
        for file in project["accepted_files"]
        if file["path"] in project.get("_contents", {})
    }

    if not contents:
        # Refusing beats inventing. Scoring an empty project would return a
        # perfect 100 with nothing behind it — meaningless, and trivially
        # gamed by submitting a folder of images.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="This project has no analysable file. Nothing to report.",
        )

    result = report.analyse_project(contents, use_llm=use_llm)
    result["project_id"] = project_id

    # Tell the submitter what happened. A failure to notify must never fail
    # the analysis that triggered it — the report is the product, the
    # notification is a courtesy on top of it — so deliver() never raises.
    notifications.notify_report(result, project["owner"], project.get("name"))

    return result
