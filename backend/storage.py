"""Temporary in-memory storage for analyses and projects.

Limits accepted for now:
  - everything is lost when the server restarts;
  - it does not work with several uvicorn workers (each would have its own
    list);
  - looking up by id walks the whole list.

All three disappear when SQLite replaces this file. The rest of the project
will not need to change: only the functions below are rewritten.

Important rule: this module knows nothing about HTTP. No 404 here — we
return None and the router decides what to do with it.
"""

# The _ prefix signals "internal use": go through the functions, not the
# lists directly.
_analyses: list[dict] = []
_projects: list[dict] = []


def save(analysis: dict) -> dict:
    """Store an analysis and return it."""
    _analyses.append(analysis)
    return analysis


def get_all() -> list[dict]:
    """Return every analysis, oldest first."""
    # We return a copy of the list: the caller cannot empty the store.
    return list(_analyses)


def clear() -> None:
    """Empty the store completely (analyses AND projects).

    Used by tests, so each one starts from a clean slate and does not depend
    on what another test left behind.
    """
    _analyses.clear()
    _projects.clear()


def get_by_id(analysis_id: str) -> dict | None:
    """Look up an analysis by id. Returns None if it does not exist."""
    for analysis in _analyses:
        if analysis["id"] == analysis_id:
            return analysis
    return None


# --------------------------------------------------------------------------
# Projects — same pattern, same limits, same future replacement by SQLite.
# --------------------------------------------------------------------------


def save_project(project: dict) -> dict:
    """Store a project and return it."""
    _projects.append(project)
    return project


def get_all_projects() -> list[dict]:
    """Return every project, oldest first."""
    return list(_projects)


def get_project_by_id(project_id: str) -> dict | None:
    """Look up a project by id. Returns None if it does not exist."""
    for project in _projects:
        if project["project_id"] == project_id:
            return project
    return None
