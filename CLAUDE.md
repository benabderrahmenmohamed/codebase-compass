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

**Every feature is measured against that sentence.** Persistence, roles and
notifications are deliverables from the brief and they earn their place by serving it —
notifications exist to tell someone about a problem in unfamiliar code *when they are
not watching the screen*, not because notifications are a nice thing to have.

### The principle everything follows from

> **Rules find the candidates. The LLM supplies the meaning.**
>
> The LLM never scans for problems and never sees the whole codebase — only a compact
> skeleton plus windows around things already flagged.

This keeps cost predictable, output verifiable, and every layer testable offline.

## Architecture

| Layer | Tech | Location |
|---|---|---|
| Frontend | React (**JavaScript, never TypeScript**) + Vite, on `:5173` | `frontend/` |
| Backend | Python FastAPI + Pydantic v2, on `:8000` | `backend/` (venv inside) |
| Static analysis | Semgrep with our own 11-rule pack | `backend/rules/quality.yaml` |
| LLM layer | `claude-opus-5`, structured output, verified | `backend/analysis/claude_client.py` |
| MCP server | 6 read-only tools, no filesystem access | `backend/mcp_server/server.py` |
| Database | SQLite, one JSON document per record | `backend/storage.py` |
| Sources | picked folder, or a public GitHub repository | `backend/analysis/github_source.py` |

### Backend layout

```
backend/
  main.py                    app creation, CORS, include_router
  schemas.py                 Pydantic models = the API contract AND the LLM's output contract
  storage.py                 SQLite: analyses, projects, users
  settings.py                environment: API key, GitHub token, db path
  permissions.py             roles and the permission matrix — pure policy, no HTTP
  rule_engine.py             LEGACY regex engine, still serving POST /analyses
  rules/quality.yaml         our Semgrep rules, carrying category/severity/penalty
  routers/
    analyses.py              snippet mode
    projects.py              folder or GitHub repository, then analysis
    users.py                 roles, /users/me
    security.py              the ONLY file turning a permission decision into 401/403
  analysis/
    ingestion.py             filter, bound and re-validate a submitted project
    github_source.py         fetch a public repo: parse owner/repo, tree, raw contents
    semgrep_runner.py        subprocess, cache, visible degradation
    skeleton.py              ast symbols, import graph, entry points, reading order
    metrics.py naming.py clones.py     the deterministic detectors
    findings.py              one Finding type; dedupe, rank, cap
    scoring_config.py        every threshold and weight
    scoring.py               worst-finding security, density elsewhere, A–E
    context.py               skeleton + focus windows, and the explanation cap
    claude_client.py         the only file that calls the Anthropic API
    report.py                assembly, and what could NOT be done
  tests/                     433 tests, all offline, no API key
frontend/src/
  api.js projectFiles.js github.js     no component knows a server exists
  components/                ProjectPicker, ProjectReport, AnalysisReport
  tests/                     92 tests, offline (fetch is stubbed to throw)
```

Each file has one job. The seam files exist so a future change touches exactly one file
— **proven twice now**: the analysis engine was rewritten end to end, and storage moved
from a dict to SQLite, both without changing a single caller or test.

## Conventions

- **English everywhere.** Identifiers, comments, docstrings, test names, JSON keys.
- JSON keys are ASCII snake_case: `security`, `readability`, `maintainability`,
  `performance`, `best_practices`.
- Timestamps are UTC, ISO 8601.
- `total_score` is always computed server-side, never sent by a client.
- **Paths from a client are data, not truth** — always re-validated server-side. The
  same applies to paths from GitHub.
- **Degradation must be visible.** A layer that cannot run says so; it never returns an
  empty result that reads as "all clear". A cap that drops something reports the count.
- Layers never know about HTTP. `ingestion.py` raises `LimitExceeded`, `permissions.py`
  raises `PermissionDenied`; the routers turn those into 413 and 403.
- **A defect found in use becomes a named test.**

## What a run costs — measured, not estimated

| Project | Cost | Latency |
|---|---|---|
| 47-line demo, 8 findings | $0.098 | ~55 s |
| 60-file repository, 100 findings | $0.22 | ~97 s |

**Output is 93% of the bill.** Cost tracks how much the model has to WRITE, not how much
code is sent — which is why `context.py` caps explanations at the worst 15 findings, and
why guests cannot trigger the paid layer at all.

## Run it

```bash
cd backend && venv/Scripts/activate && uvicorn main:app --reload   # http://localhost:8000/docs
cd frontend && npm run dev                                        # http://localhost:5173
cd backend && venv/Scripts/python.exe -m pytest -q                 # 433 tests
cd frontend && npm test                                            # 92 tests
```

## Deliverables from the encadreur

| Deliverable | State |
|---|---|
| Endpoints list with expected responses | done — Pydantic → `/docs` → `/openapi.json` |
| E2E testing | done — 525 tests, all offline |
| Vulnerability analysis | done — no ZIP, no URL fetch, SSRF defence, path re-validation |
| Scoring system | done — worst-finding + density, A–E, coverage flags |
| Data structure | done — SQLite |
| Roles / permissions | done — 4 roles, matrix enforced at the router |
| **Notifications list** | **next** |
| Cahier des charges · functionality list · flows | not written |

## How to work with me

- **I am here to learn.** Never write large amounts of code without explaining it.
- Explain the *why* of each choice, briefly, **before** writing the code.
- **Work in SMALL steps: one feature at a time, then stop and let me run it.**
  Do not chain four features together and self-verify — I cannot learn from a diff I
  did not watch happen.
- Prefer simple, readable solutions over clever ones.
- Keep JavaScript (no TypeScript). Keep the current folder structure.
- **Do not add layers I did not ask for.** Auth and the database were in the brief, so
  they are in. Anything not in the brief needs asking first.
- This is going on GitHub as open source: treat hostile input as normal, not exceptional.
