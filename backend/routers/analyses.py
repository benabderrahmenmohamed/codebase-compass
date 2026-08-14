"""Endpoints for the "analyses" domain.

An APIRouter groups the routes of one subject together. main.py then only has
to include it, and stays short.
"""

from fastapi import APIRouter, HTTPException, status

import storage
from rule_engine import build_analysis
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
def create_analysis(payload: AnalysisRequest):
    """Analyse the received code, store the report and return it.

    `payload` is already validated by Pydantic when we get here: if the code
    was empty or missing, FastAPI already answered 422 without running this.
    """
    analysis = build_analysis(payload.code, payload.language)
    storage.save(analysis)
    return analysis


@router.get(
    "",
    response_model=list[AnalysisResponse],
    summary="List every analysis",
)
def list_analyses():
    """Return the full history, oldest first."""
    return storage.get_all()


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
def get_analysis(analysis_id: str):
    """Return one analysis, or 404 if the id is unknown."""
    analysis = storage.get_by_id(analysis_id)
    if analysis is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found",
        )
    return analysis
