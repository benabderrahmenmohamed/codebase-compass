# Codebase Compass

[![CI](https://github.com/benabderrahmenmohamed/codebase-compass/actions/workflows/ci.yml/badge.svg)](https://github.com/benabderrahmenmohamed/codebase-compass/actions/workflows/ci.yml)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

**Understand a codebase you didn't write.**

Most code analysis tools answer *"is this code good?"*. This one answers a harder and
more useful question:

> **"I've been dropped into a project I don't know. Help me understand it — and show me
> what I'm not experienced enough to notice yet."**

A linter can tell you that `x` is a bad variable name. It cannot tell you that **`x`
holds a token expiry date**. That gap is where junior developers get stuck, and closing
it is what this project is for.

> ⚠️ **Early days.** Every layer is built and tested; the AI review has not yet been run
> against the live API. See [Status](#status).

---

## What it produces

Not a list of complaints — an onboarding document, ordered the way someone new actually
needs it:

| # | Section | Answers |
|---|---|---|
| 1 | Overview | What is this? Stack, entry points |
| 2 | How to run it | Dependencies, expected environment variables, launch command |
| 3 | Project map | Annotated file tree; what depends on what |
| 4 | Where to start reading | 4–5 files in order, each with *why* |
| 5 | Trace one feature | A single request followed end to end |
| 6 | **Symbols to clarify** | `x` → *holds the token expiry, UTC* → `expiry_date` |
| 7 | Priority problems | Why it matters · how to fix · what you learn |
| 8 | Good first contributions | 3–5 safe fixes, ranked easy → harder |
| 9 | Questions for the team | What the analysis raises but cannot settle |
| 10 | Code health | 5 scores out of 20, plus an A–E rating |

**Section 6 is the point.** It is not criticism — it is translation:

| Current name | What it actually holds | Suggested name |
|---|---|---|
| `x` | The token expiry date, in UTC | `expiry_date` |
| `data` | The JSON response from the payment API | `payment_response` |
| `flag` | True if the user confirmed their email | `email_confirmed` |

---

## How it works

> **Rules find the candidates. The LLM supplies the meaning.**

The model never scans code looking for problems, and never sees a whole codebase — only
a compact skeleton plus small windows around things already flagged by deterministic
tools. That keeps cost roughly **$0.01–0.05 per project**, keeps the output verifiable,
and means a complete report still exists when the LLM is unavailable.

```
   project files
        │
   ┌────▼──────────────────────────────────────┐
   │ 1. Ingestion    filter · bound · validate  │  free, offline
   │ 2. Skeleton     graph · entry points       │  free, offline
   │ 3. Detectors    semgrep · metrics · clones │  free, offline
   │ 4. Selection    rank · focus windows       │  free, offline
   │ 5. Claude       explain · name · orient    │  optional
   │ 6. Scoring      worst-finding · density    │  free, offline
   └────────────────────────────────────────────┘
```

**Every layer degrades visibly.** If Semgrep is missing or the LLM is unreachable, the
report says so — it never returns an empty result that reads as "all clear".

### Scoring

Borrowed from SonarQube, whose real insight is that different qualities score
differently:

- **Security** is driven by the **worst** finding. One SQL injection is critical in a
  5-line file and in a 5000-line file; size is irrelevant to exploitability.
- **Everything else** is scored by **density** per 100 lines. Three long lines in 30 is
  sloppy; three in 500 is noise.

---

## Status

| | Component | State |
|---|---|---|
| ✅ | Project ingestion: allowlist, limits, path-traversal defence | working |
| ✅ | Skeleton: `ast` symbols, import graph, entry points, reading order | working |
| ✅ | Semgrep runner: own rule pack, one-subprocess scan, visible degradation | working |
| ✅ | Detectors: metrics, weak names, magic numbers, duplicate functions | working |
| ✅ | Scoring: worst-finding security, density elsewhere, A–E grade | working |
| ✅ | Context selection: skeleton + focus windows inside a token budget | working |
| ✅ | Claude layer: structured output, verification, 9 classified failure paths | working |
| ✅ | MCP server: 6 tools the model can call on demand | working |
| ✅ | REST API + React frontend, folder picker and full report | working |
| ✅ | **275 tests**, all offline, no API key needed, ~12 seconds | working |
| 🔜 | First run against the live API | next |
| 🔜 | Manifest files (`requirements.txt`, `package.json`) for "how to run it" | planned |
| 🔜 | SQLite persistence, accounts, notifications | planned |

Measured on this project's own backend: **39 files scanned in under a second**, and the
payload sent to the model is **22% of the source** — a map plus the twenty most serious
code sites, not 178,000 characters.

---

## Install

Requires **Python 3.11+** and **Node 18+**.

```bash
git clone https://github.com/benabderrahmenmohamed/codebase-compass.git
cd codebase-compass
```

**Backend**

```bash
cd backend
python -m venv venv
venv/Scripts/activate          # Windows;  source venv/bin/activate on macOS/Linux
pip install -r requirements.txt
uvicorn main:app --reload
```

API docs: <http://localhost:8000/docs>

**Frontend**

```bash
cd frontend
npm install
npm run dev
```

App: <http://localhost:5173>

**Tests**

```bash
cd backend
pytest -q          # 275 tests, offline, no API key needed
```

The suite runs with no key and no network: an autouse fixture blanks
`ANTHROPIC_API_KEY` and blocks every non-loopback socket, so a test that
tried to reach the real API would fail loudly rather than quietly bill you.

---

## API

| Method | Path | Returns |
|---|---|---|
| `POST` | `/analyses` | `201` + report — `422` if the code is empty or missing |
| `GET` | `/analyses` | `200` + history |
| `GET` | `/analyses/{id}` | `200` + report — `404` if unknown |
| `POST` | `/projects` | `201` + accepted/skipped files — `413` if a limit is exceeded |
| `GET` | `/projects` | `200` + history |
| `GET` | `/projects/{id}` | `200` + project — `404` if unknown |
| `POST` | `/projects/{id}/analysis` | `200` + full report — `404` unknown, `422` nothing analysable |

Submission and analysis are separate calls on purpose: ingestion answers instantly, so the
user sees *"39 files accepted, 0 skipped"* while Semgrep and the model work.

Add `?use_llm=false` to get the deterministic report only — no API call, no cost, everything
except the written explanations.

### The API key

Optional. Without it you get the file map, the findings, the scores and the grade; the report
states that the explanations are missing rather than pretending they were unnecessary.

```bash
cd backend
cp .env.example .env      # then paste your key into it
```

`.env` is git-ignored. A key pushed to a public repository must be treated as compromised and
rotated, even if the commit is deleted afterwards.

Interactive documentation is generated from the Pydantic models and served at `/docs`;
the machine-readable version is at `/openapi.json`.

### Submission limits

| Limit | Value |
|---|---|
| Files per project | 200 |
| Characters per file | 50,000 |
| Characters per project | 2,000,000 |
| Extensions analysed | `.py .js .jsx .ts .tsx .java .php .go .rb` |

Files outside those extensions, and anything under `node_modules`, `venv`, `.git`,
`dist`, `build` or `__pycache__`, are **skipped and reported** — never a silent drop,
and never a reason to reject the whole submission.

---

## Security notes

This tool ingests untrusted source code by design, so a few decisions are deliberate:

- **No ZIP upload.** Archives bring Zip Slip (an entry named `../../etc/passwd`
  overwriting files outside the extraction directory) and zip bombs. Choosing an input
  format that does not have the vulnerability beats defending against it.
- **No Git URL fetching.** A server that fetches a user-supplied URL is a textbook SSRF
  risk.
- **Client paths are re-validated server-side** — `..` segments, absolute paths, drive
  letters, control characters, null bytes and reserved Windows names are all rejected.
- **Semgrep runs with `--metrics=off`.** It sends usage telemetry by default; submitted
  code must not leave the machine.
- **Submitted code is written to an isolated temp directory** and removed in a `finally`
  block, so it never persists.

---

## Contributing

Contributions are welcome. Before opening a pull request:

1. `pytest -q` must pass — all tests are offline and take under two seconds.
2. New behaviour comes with a test. Bugs found in use become permanent tests.
3. Everything is in English: identifiers, comments, docstrings, test names.
4. Keep JavaScript on the frontend — no TypeScript.
5. Layers stay independent: analysis code must not know about HTTP.

---

## Licence

[MIT](LICENSE) — do anything you like with it, just keep the copyright notice.

## Acknowledgements

Prior art that shaped the design:

- [alibaba/open-code-review](https://github.com/alibaba/open-code-review) — hybrid
  deterministic + LLM architecture
- [SonarQube](https://www.sonarsource.com/) — the scoring model
- [code-graph-rag](https://github.com/vitali87/code-graph-rag) — representing a codebase
  as a graph
- [Semgrep](https://semgrep.dev/) — the static analysis engine
