"""Endpoints for the "analyses" domain.

An APIRouter groups the routes of one subject together. main.py then only has
to include it, and stays short.
"""

from fastapi import APIRouter, HTTPException, status

import permissions
import storage
from permissions import User
from routers import security
from analysis import snippet
from schemas import AnalysisRequest, AnalysisResponse, ErrorResponse

# prefix: every route below starts with /analyses
# tags:   the group title on the /docs page
router = APIRouter(prefix="/analyses", tags=["Analyses"])


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=AnalysisResponse,
    summary="Submit code to analyse",
)
def create_analysis(payload: AnalysisRequest, user: User = security.CurrentUser):
    """Analyse the received code, store the report and return it.

    `payload` is already validated by Pydantic when we get here: if the code
    was empty or missing, FastAPI already answered 422 without running this.
    """
    security.require(user, permissions.SUBMIT_SNIPPET)

    analysis = snippet.analyse(payload.code, payload.language)
    # Ownership is recorded at creation. Without it, "show me my analyses"
    # has no answer and every report is everybody's.
    analysis["owner"] = user.name
    storage.save(analysis)
    return analysis


@router.get(
    "",
    response_model=list[AnalysisResponse],
    summary="List every analysis",
)
def list_analyses(user: User = security.CurrentUser):
    """Return the history this user may see, oldest first.

    A lead or an admin sees everything; everyone else sees their own. The
    filtering happens here rather than in storage, because "may see" is a
    policy question and storage does not do policy.
    """
    return permissions.visible_to(user, storage.get_all())


@router.get(
    "/{analysis_id}",
    response_model=AnalysisResponse,
    summary="Fetch one analysis by id",
    # FastAPI cannot guess that we raise a 404: we document it here.
    responses={
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "No analysis carries this id",
        }
    },
)
def get_analysis(analysis_id: str, user: User = security.CurrentUser):
    """Return one analysis, or 404 if the id is unknown or not yours."""
    analysis = storage.get_by_id(analysis_id)
    if analysis is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found",
        )
    security.require_readable(user, analysis, "Analysis")
    return analysis
