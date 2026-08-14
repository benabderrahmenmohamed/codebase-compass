// Displays an analysis report. This component does not know where the report
// came from: it receives an object as a prop and simply draws it.

// The API keys are ASCII snake_case (security, best_practices). Display
// labels live here, in the interface. The order of this object also fixes
// the display order: we do not depend on the key order the server returns.
const LABELS = {
  security: 'Security',
  readability: 'Readability',
  maintainability: 'Maintainability',
  performance: 'Performance',
  best_practices: 'Best practices',
}

// Label and sort order for severities (0 = worst, shown first).
const SEVERITIES = {
  critical: { label: 'Critical', rank: 0 },
  high: { label: 'High', rank: 1 },
  medium: { label: 'Medium', rank: 2 },
  low: { label: 'Low', rank: 3 },
}

function AnalysisReport({ report }) {
  // [...] makes a COPY before sorting: sort() mutates the original array,
  // and a prop must never be mutated.
  const sortedIssues = [...report.issues].sort(
    (a, b) => SEVERITIES[a.severity].rank - SEVERITIES[b.severity].rank
  )

  return (
    <section className="report">
      <div className="total">
        <span className="total-score">{report.total_score}</span>
        <span className="total-max">/ 100</span>
        <p className="total-meta">
          {report.language} — analysed on{' '}
          {/* The server stores UTC, the browser shows local time. */}
          {new Date(report.created_at).toLocaleString()}
        </p>
      </div>

      <h2>Scores by category</h2>
      <ul className="scores">
        {Object.entries(LABELS).map(([key, label]) => (
          <li key={key}>
            <div className="score-row">
              <span>{label}</span>
              <strong>{report.scores[key]} / 20</strong>
            </div>
            <div className="gauge">
              <div
                className="gauge-fill"
                style={{ width: `${(report.scores[key] / 20) * 100}%` }}
              />
            </div>
          </li>
        ))}
      </ul>

      <h2>
        Problems found <span className="count">{sortedIssues.length}</span>
      </h2>
      <ul className="issues">
        {sortedIssues.map((issue, index) => (
          <li key={index} className={`issue issue-${issue.severity}`}>
            <div className="issue-header">
              <span className="badge">{SEVERITIES[issue.severity].label}</span>
              <span className="line">line {issue.line}</span>
            </div>
            <p className="issue-message">{issue.message}</p>
            <p className="issue-suggestion">{issue.suggestion}</p>
          </li>
        ))}
      </ul>
    </section>
  )
}

export default AnalysisReport
