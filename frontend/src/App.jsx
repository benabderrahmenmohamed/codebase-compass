import { useState } from 'react'
import { analyseProject, analyzeCode, submitProject } from './api'
import AnalysisReport from './components/AnalysisReport'
import ProjectPicker from './components/ProjectPicker'
import ProjectReport from './components/ProjectReport'
import './App.css'

function App() {
  const [mode, setMode] = useState('project')

  // Snippet mode
  const [code, setCode] = useState('')
  const [language, setLanguage] = useState('')
  const [snippetReport, setSnippetReport] = useState(null)

  // Project mode
  const [projectReport, setProjectReport] = useState(null)
  const [manifest, setManifest] = useState(null)

  // Shared request state
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  function reset() {
    setError(null)
    setSnippetReport(null)
    setProjectReport(null)
    setManifest(null)
  }

  async function handleSnippet(event) {
    event.preventDefault()
    reset()
    setLoading(true)
    try {
      setSnippetReport(await analyzeCode(code, language))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  // `source` is { files } for an uploaded folder or { repo } for GitHub.
  async function handleProject(source, name) {
    reset()
    setLoading(true)
    try {
      // Two calls: submission answers instantly, so the user sees what was
      // accepted while the analysis runs. For a GitHub project the first
      // call also does the fetching, so it is slower — but it is still the
      // call that reports what was found before anything is analysed.
      const submitted = await submitProject(source, name)
      setManifest(submitted)
      setProjectReport(await analyseProject(submitted.project_id))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="app">
      <header className="masthead">
        <h1>Codebase Compass</h1>
        <p className="tagline">
          Static analysis and AI review for Python and JavaScript projects —
          code you have just inherited, or code you have just written.
        </p>
        <ul className="capabilities">
          <li>
            <strong>Structure map</strong>
            Files, imports, entry points, and a reading order computed from the
            import graph rather than guessed.
          </li>
          <li>
            <strong>Ranked findings</strong>
            Security, performance, readability, maintainability and best
            practices — each with why it matters and how to fix it.
          </li>
          <li>
            <strong>Symbol translation</strong>
            What an unclear name actually holds, and what it should be called.
          </li>
          <li>
            <strong>Health score</strong>
            Five categories out of 20, with an A–E grade and what was
            measured to reach it.
          </li>
        </ul>
      </header>

      <nav className="tabs">
        <button
          type="button"
          className={mode === 'project' ? 'active' : ''}
          onClick={() => {
            setMode('project')
            reset()
          }}
        >
          Whole project
        </button>
        <button
          type="button"
          className={mode === 'snippet' ? 'active' : ''}
          onClick={() => {
            setMode('snippet')
            reset()
          }}
        >
          Single snippet
        </button>
      </nav>

      {mode === 'project' ? (
        <ProjectPicker onAnalyse={handleProject} busy={loading} />
      ) : (
        <form onSubmit={handleSnippet} className="form">
          <label htmlFor="code">Source code</label>
          <textarea
            id="code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            rows={14}
            spellCheck={false}
            placeholder={'def get_user(user_id):\n    ...'}
          />

          <label htmlFor="language">Language (optional)</label>
          <input
            id="language"
            value={language}
            onChange={(e) => setLanguage(e.target.value)}
            placeholder="python, javascript, java..."
          />

          <button type="submit" disabled={loading || code.trim() === ''}>
            {loading ? 'Analysing…' : 'Analyse code'}
          </button>
        </form>
      )}

      {error && <p className="error">{error}</p>}

      {manifest && (
        <p className="manifest">
          {manifest.source === 'github' && manifest.repo_url && (
            <>
              <a href={manifest.repo_url} target="_blank" rel="noreferrer">
                {manifest.name}
              </a>
              {' · '}
            </>
          )}
          {manifest.accepted_files.length} files accepted
          {manifest.skipped.length > 0 && `, ${manifest.skipped.length} skipped`}
          {/* A truncated listing means files exist that were never even
              seen — different from files seen and skipped, and the only
              honest way to show a partial analysis. */}
          {manifest.truncated &&
            ' · the repository was too large to list in full, so some files were never seen'}
        </p>
      )}

      {projectReport && <ProjectReport report={projectReport} />}
      {snippetReport && <AnalysisReport report={snippetReport} />}

      {(projectReport || snippetReport) && (
        <details className="raw">
          <summary>Show the raw API response</summary>
          <pre>{JSON.stringify(projectReport ?? snippetReport, null, 2)}</pre>
        </details>
      )}
    </main>
  )
}

export default App
