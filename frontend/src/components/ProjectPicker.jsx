import { useRef, useState } from 'react'
import { planUpload, readFiles } from '../projectFiles'

// Pick a folder, see what will be sent, then send it.
//
// webkitdirectory lets the browser walk a whole folder. It is non-standard
// but supported everywhere current (Baseline 2025), and it avoids ZIP
// upload entirely — which means avoiding Zip Slip and zip bombs rather
// than defending against them.

function ProjectPicker({ onAnalyse, busy }) {
  const [plan, setPlan] = useState(null)
  const [name, setName] = useState('')
  const [reading, setReading] = useState(false)
  const dropRef = useRef(null)

  async function choose(fileList) {
    if (!fileList || fileList.length === 0) return

    setReading(true)
    try {
      const planned = planUpload(fileList)
      const read = await readFiles(planned.toSend)
      setPlan({
        files: read.files,
        skipped: [...planned.skipped, ...read.skipped],
        totalChars: read.totalChars,
        picked: fileList.length,
      })
    } finally {
      setReading(false)
    }
  }

  function handleDrop(event) {
    event.preventDefault()
    dropRef.current?.classList.remove('over')
    choose(event.dataTransfer.files)
  }

  const reasons = {}
  for (const item of plan?.skipped ?? []) {
    reasons[item.reason] = (reasons[item.reason] ?? 0) + 1
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
            onChange={(e) => choose(e.target.files)}
          />
        </label>
        <p className="hint">
          Nothing is uploaded until you press Analyse. Dependency folders and
          non-code files are dropped here, before anything leaves your machine.
        </p>
      </div>

      {reading && <p className="reading">Reading files…</p>}

      {plan && (
        <div className="plan">
          <p>
            <strong>{plan.files.length}</strong> file
            {plan.files.length === 1 ? '' : 's'} ready ·{' '}
            {Math.round(plan.totalChars / 1000)} k characters ·{' '}
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

          <button
            type="button"
            disabled={busy || plan.files.length === 0}
            onClick={() => onAnalyse(plan.files, name)}
          >
            {busy ? 'Analysing…' : `Analyse ${plan.files.length} files`}
          </button>
        </div>
      )}
    </section>
  )
}

export default ProjectPicker
