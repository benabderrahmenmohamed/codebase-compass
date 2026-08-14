"""Endpoints for the "projects" domain.

A project is a set of files submitted together. This endpoint does the
reception ONLY: filter, bound, store. Analysis comes later.
"""

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status

import storage
from analysis import ingestion, report
from schemas import (
    ErrorResponse,
    ProjectAnalysisResponse,
    ProjectResponse,
    ProjectSubmission,
)

router = APIRouter(prefix="/projects", tags=["Projects"])


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=ProjectResponse,
    summary="Submit a project to analyse",
    responses={
        status.HTTP_413_CONTENT_TOO_LARGE: {
            "model": ErrorResponse,
            "description": "A limit was exceeded (detailed message)",
        }
    },
)
def create_project(payload: ProjectSubmission):
    """Receive a project, skip what is not analysable, store the rest.

    A non-conforming file is SKIPPED (and listed in `skipped`); only an
    exceeded limit refuses the whole submission, with a 413.
    """
    try:
        result = ingestion.prepare(payload.files)
    except ingestion.LimitExceeded as exceeded:
        # The ingestion layer knows nothing about HTTP: this is where its
        # domain exception is translated into a status code.
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=str(exceeded),
        ) from exceeded

    project = {
        "project_id": str(uuid4()),
        "name": payload.name,
        "accepted_files": [file._asdict() for file in result.accepted],
        "skipped": [file._asdict() for file in result.skipped],
        "total_chars": result.total_chars,
        "created_at": datetime.now(timezone.utc),
        # Contents are kept separately: they never appear in the response
        # (response_model filters them out), but the next layers need them.
        "_contents": {
            ingestion.normalise(f.path): f.content
            for f in payload.files
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
def list_projects():
    """Return the full history, oldest first."""
    return storage.get_all_projects()


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
def get_project(project_id: str):
    """Return one project, or 404 if the id is unknown."""
    project = storage.get_project_by_id(project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
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
def analyse_project(project_id: str, use_llm: bool = True):
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
    return result
