# Codebase Compass

**Everything in this repository is written in English** — code, comments, docstrings,
tests, API keys, UI strings, docs. No French anywhere.

## What the tool is for

Not "is this code good?" but:

> **"I've been dropped into a codebase I don't know. Help me understand it —
> and show me what I'm not experienced enough to notice yet."**

A linter can say `x` is a bad name. It cannot say **what `x` holds**. That gap is where
juniors get stuck, and it is what an LLM is good at — provided it is pointed at the
right lines.

### The principle everything follows from

> **Rules find the candidates. The LLM supplies the meaning.**
>
> The LLM never scans for problems and never sees the whole codebase — only a compact
> skeleton plus windows around things already flagged.

This keeps cost predictable (~$0.01–0.05 per project), output verifiable, and every
layer testable offline.

## Architecture

| Layer | Tech | Location |
|---|---|---|
| Frontend | React (**JavaScript, never TypeScript**) + Vite, on `:5173` | `frontend/` |
| Backend | Python FastAPI + Pydantic v2, on `:8000` | `backend/` (venv inside) |
| Static analysis | Semgrep with our own rule pack | `backend/rules/quality.yaml` |
| LLM layer | MCP server calling the Claude API | not built yet |
| Database | in-memory for now; SQLite later | `backend/storage.py` |

### Backend layout

```
backend/
  main.py                    app creation, CORS, include_router
  schemas.py                 Pydantic models = the API contract
  storage.py                 in-memory store — SQLite replaces this, nothing else changes
  rule_engine.py             rule-based analysis — the SEAM the LLM plugs into
  rules/quality.yaml         our Semgrep rules, carrying category/severity/penalty
  routers/
    analyses.py              POST /analyses, GET /analyses, GET /analyses/{id}
    projects.py              POST /projects, GET /projects, GET /projects/{id}
  analysis/
    ingestion.py             filter, bound and validate a submitted project
    semgrep_runner.py        subprocess, cache, visible degradation
  tests/                     76 tests, all offline
```

Each file has one job. The seam files exist so that adding the real LLM or a real
database touches exactly one file each — already proven once: the analysis engine was
rewritten end to end without changing anything else.

## Conventions

- **English everywhere.** Identifiers, comments, docstrings, test names, JSON keys.
- JSON keys are ASCII snake_case: `security`, `readability`, `maintainability`,
  `performance`, `best_practices`.
- Timestamps are UTC, ISO 8601.
- `total_score` is always computed server-side as the sum of the five category scores,
  never sent by a client.
- **Paths from a client are data, not truth** — always re-validated server-side.
- **Degradation must be visible.** A layer that cannot run says so; it never returns an
  empty result that reads as "all clear".
- Layers never know about HTTP. `ingestion.py` raises `LimitExceeded`; the router turns
  it into a 413.

## Run it

```bash
cd backend && venv/Scripts/activate && uvicorn main:app --reload   # http://localhost:8000/docs
cd frontend && npm run dev                                        # http://localhost:5173
cd backend && venv/Scripts/python.exe -m pytest -q                 # 76 tests
```

## How to work with me

- **I am here to learn.** Never write large amounts of code without explaining it.
- Explain the *why* of each choice, briefly, before writing the code.
- Prefer simple, readable solutions over clever ones.
- Keep JavaScript (no TypeScript). Keep the current folder structure.
- Do not add unrequested layers (auth, databases, extra abstractions).
- This is going on GitHub as open source: treat hostile input as normal, not exceptional.
