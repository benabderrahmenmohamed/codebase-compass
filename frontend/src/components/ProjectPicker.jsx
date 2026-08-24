import { useRef, useState } from 'react'
import {
  formatChars,
  fromDataTransfer,
  fromFileList,
  planUpload,
  readFiles,
} from '../projectFiles'
import { parseRepoReference, repoSlug } from '../github'

// A project arrives one of two ways: a folder from this machine, or a public
// GitHub repository the server fetches.
//
// The folder path uses webkitdirectory, which lets the browser walk a whole
// directory. It is non-standard but supported everywhere current, and it
// avoids ZIP upload entirely — which means avoiding Zip Slip and zip bombs
// rather than defending against them.
//
// ONE SOURCE AT A TIME. Choosing either clears the other, and says so. The
// API refuses a submission carrying both, because a single report cannot
// describe two different projects and picking one silently would show
// someone a grade for code they were not looking at. Rather than let the
// user build a request that will be rejected, the interface makes it
// impossible to express — and the rejection stays in place for callers
// that have no interface.

function ProjectPicker({ onAnalyse, busy }) {
  const [plan, setPlan] = useState(null)
  const [repo, setRepo] = useState('')
  const [name, setName] = useState('')
  const [reading, setReading] = useState(false)
  const [failed, setFailed] = useState(null)
  const [cleared, setCleared] = useState(null)
  const dropRef = useRef(null)

  // `entries` are { file, path } pairs; `preSkipped` are things already
  // rejected during the walk, such as a pruned node_modules.
  async function choose(entries, preSkipped = []) {
    if (entries.length === 0) return

    setReading(true)
    setFailed(null)
    try {
      const planned = planUpload(entries)
      const read = await readFiles(planned.toSend)
      setPlan({
        files: read.files,
        skipped: [...preSkipped, ...planned.skipped, ...read.skipped],
        totalChars: read.totalChars,
        picked: entries.length + preSkipped.length,
      })
      if (repo.trim()) {
        setRepo('')
        setCleared('The repository was cleared — one source at a time.')
      } else {
        setCleared(null)
      }
    } catch (e) {
      // A folder can become unreadable between the drop and the read, and a
      // rejected promise here would otherwise vanish with no message at all.
      setPlan(null)
      setFailed(e.message || 'Those files could not be read.')
    } finally {
      setReading(false)
    }
  }

  async function handleDrop(event) {
    event.preventDefault()
    dropRef.current?.classList.remove('over')
    setReading(true)
    try {
      // Must read the DataTransfer before awaiting anything: it is emptied as
      // soon as this handler returns.
      const { entries, skipped } = await fromDataTransfer(event.dataTransfer)
      await choose(entries, skipped)
    } catch (e) {
      setPlan(null)
      setFailed(e.message || 'That folder could not be read.')
    } finally {
      setReading(false)
    }
  }

  function handleRepoChange(value) {
    setRepo(value)
    setFailed(null)
    if (value.trim() && plan) {
      setPlan(null)
      setCleared('The chosen folder was cleared — one source at a time.')
    } else if (!value.trim()) {
      setCleared(null)
    }
  }

  const trimmedRepo = repo.trim()
  const parsedRepo = parseRepoReference(trimmedRepo)
  const repoIsUnusable = trimmedRepo.length > 0 && parsedRepo === null

  const reasons = {}
  for (const item of plan?.skipped ?? []) {
    reasons[item.reason] = (reasons[item.reason] ?? 0) + 1
  }

  function submit() {
    if (parsedRepo) onAnalyse({ repo: trimmedRepo }, name)
    else if (plan?.files.length) onAnalyse({ files: plan.files }, name)
  }

  return (
    <section className="picker">
      <label htmlFor="project-name">Project name (optional)</label>
      <input
        id="project-name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder="order-service"
      />

      <label htmlFor="repo">Public GitHub repository</label>
      <input
        id="repo"
        value={repo}
        onChange={(e) => handleRepoChange(e.target.value)}
        placeholder="https://github.com/owner/repo"
        spellCheck={false}
        aria-invalid={repoIsUnusable}
      />
      {repoIsUnusable && (
        <p className="hint hint-warn">
          That is not a GitHub repository. Paste a github.com URL, or{' '}
          <code>owner/repo</code>. Other hosts are not fetched.
        </p>
      )}
      {parsedRepo && (
        <p className="hint">
          Will analyse <code>{repoSlug(trimmedRepo)}</code>
          {parsedRepo.ref && (
            <>
              {' '}
              on branch <code>{parsedRepo.ref}</code>
            </>
          )}
          . Only public repositories can be read.
        </p>
      )}

      <p className="separator">or</p>

      <div
        ref={dropRef}
        className="dropzone"
        onDragOver={(e) => {
          e.preventDefault()
          dropRef.current?.classList.add('over')
        }}
        onDragLeave={() => dropRef.current?.classList.remove('over')}
        onDrop={handleDrop}
      >
        <p>Drop a folder here, or</p>
        <label className="file-button">
          Choose a folder
          {/* webkitdirectory is set through a ref-free attribute because
              React does not know this non-standard property by name. */}
          <input
            type="file"
            multiple
            webkitdirectory=""
            directory=""
            onChange={(e) => choose(fromFileList(e.target.files))}
          />
        </label>
        <p className="hint">
          Nothing is uploaded until you press Analyse. Dependency folders and
          non-code files are dropped here, before anything leaves your machine.
        </p>
      </div>

      {reading && <p className="reading">Reading files…</p>}
      {failed && <p className="error">{failed}</p>}
      {cleared && <p className="hint hint-cleared">{cleared}</p>}

      {plan && (
        <div className="plan">
          <p>
            <strong>{plan.files.length}</strong> file
            {plan.files.length === 1 ? '' : 's'} ready ·{' '}
            {formatChars(plan.totalChars)} ·{' '}
            <strong>{plan.skipped.length}</strong> skipped of {plan.picked}{' '}
            picked
          </p>

          {plan.skipped.length > 0 && (
            <details>
              <summary>What will not be sent, and why</summary>
              <ul className="reasons">
                {Object.entries(reasons).map(([reason, count]) => (
                  <li key={reason}>
                    <code>{reason.replace(/_/g, ' ')}</code> — {count} file
                    {count === 1 ? '' : 's'}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}

      {(parsedRepo || plan?.files.length > 0) && (
        <button
          type="button"
          className="analyse"
          disabled={busy}
          onClick={submit}
        >
          {busy
            ? 'Analysing…'
            : parsedRepo
              ? `Analyse ${repoSlug(trimmedRepo)}`
              : `Analyse ${plan.files.length} file${plan.files.length === 1 ? '' : 's'}`}
        </button>
      )}
    </section>
  )
}

export default ProjectPicker
