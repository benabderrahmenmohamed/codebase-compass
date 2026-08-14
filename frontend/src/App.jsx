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

  async function handleProject(files, name) {
    reset()
    setLoading(true)
    try {
      // Two calls: submission answers instantly, so the user sees what was
      // accepted while the analysis runs.
      const submitted = await submitProject(files, name)
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
        <h1>Understand a codebase you didn't write</h1>
        <p>
          Point it at a project: it maps the code, tells you where to start
          reading, and shows what you are not yet experienced enough to notice.
        </p>
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
          Quick check
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
          {manifest.accepted_files.length} files accepted
          {manifest.skipped.length > 0 && `, ${manifest.skipped.length} skipped`}
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
