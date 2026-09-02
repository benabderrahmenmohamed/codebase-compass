// The project report: health, map, reading order, findings.
//
// Two rules this component obeys:
//   1. A score of 20 is never shown as a clean bill of health when the
//      category was not evaluated — coverage is displayed beside it.
//   2. Anything missing says WHY it is missing. An absent section that
//      looks like an empty one is worse than no section at all.

import { incompleteBecause } from '../reportText'

const LABELS = {
  security: 'Security',
  readability: 'Readability',
  maintainability: 'Maintainability',
  performance: 'Performance',
  best_practices: 'Best practices',
}

const SEVERITIES = {
  critical: { label: 'Critical', rank: 0 },
  high: { label: 'High', rank: 1 },
  medium: { label: 'Medium', rank: 2 },
  low: { label: 'Low', rank: 3 },
}

const COVERAGE_NOTE = {
  not_evaluated: 'not evaluated — nothing measured this',
  partially_evaluated: 'partly evaluated',
}

function ProjectReport({ report }) {
  const findings = [...report.findings].sort(
    (a, b) => SEVERITIES[a.severity].rank - SEVERITIES[b.severity].rank
  )

  return (
    <section className="report">
      <div className="total">
        <span className="total-score">{report.total_score}</span>
        <span className="total-max">/ 100</span>
        {report.grade && <span className={`grade grade-${report.grade}`}>{report.grade}</span>}
        <p className="total-meta">
          {report.files.length} files · {report.findings.length} findings
          {report.findings_dropped > 0 && ` (+${report.findings_dropped} beyond the cap)`}
        </p>
      </div>

      {!report.analysis_complete && (
        <p className="warning">
          <strong>This analysis is incomplete.</strong>{' '}
          {incompleteBecause(report).join(' ')}
        </p>
      )}

      <h2>Code health</h2>
      <ul className="scores">
        {Object.entries(LABELS).map(([key, label]) => {
          const category = report.scores[key]
          const note = COVERAGE_NOTE[category.coverage]
          return (
            <li key={key}>
              <div className="score-row">
                <span>
                  {label}
                  {note && <em className="coverage"> — {note}</em>}
                </span>
                <strong>{category.score} / 20</strong>
              </div>
              <div className="gauge">
                <div
                  className={`gauge-fill${note ? ' gauge-unknown' : ''}`}
                  style={{ width: `${(category.score / 20) * 100}%` }}
                />
              </div>
            </li>
          )
        })}
      </ul>

      <h2>Overview</h2>
      {report.explanations ? (
        <p className="overview">{report.explanations.overview}</p>
      ) : (
        <p className="missing">
          No written overview: {explain(report.llm_reason)}
          {report.llm_retryable && ' Trying again may work.'}
        </p>
      )}

      <h2>Where to start reading</h2>
      {report.explanations?.reading_order?.length ? (
        <ol className="reading">
          {report.explanations.reading_order.map((step) => (
            <li key={step.path}>
              <code>{step.path}</code> — {step.why}
            </li>
          ))}
        </ol>
      ) : (
        <ol className="reading">
          {report.reading_order.map((path) => (
            <li key={path}>
              <code>{path}</code>
            </li>
          ))}
        </ol>
      )}

      {report.explanations?.symbols_to_clarify?.length > 0 && (
        <>
          <h2>Symbols to clarify</h2>
          <table className="symbols">
            <thead>
              <tr>
                <th>Where</th>
                <th>Current name</th>
                <th>What it actually holds</th>
                <th>Suggested</th>
              </tr>
            </thead>
            <tbody>
              {report.explanations.symbols_to_clarify.map((symbol, index) => (
                <tr key={index}>
                  <td>
                    <code>
                      {symbol.path}:{symbol.line}
                    </code>
                  </td>
                  <td>
                    <code>{symbol.current_name}</code>
                  </td>
                  <td>{symbol.actually_holds}</td>
                  <td>
                    <code>{symbol.suggested_name}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <h2>
        Project map <span className="count">{report.files.length}</span>
      </h2>
      <p className="hint">
        Entry points: {report.entry_points.join(', ') || 'none found'}
        {report.external_dependencies.length > 0 &&
          ` · Dependencies: ${report.external_dependencies.join(', ')}`}
      </p>
      <ul className="files">
        {report.files.map((file) => (
          <li key={file.path} className="file">
            <div className="file-head">
              <code>{file.path}</code>
              <span className="file-meta">
                {file.lines} lines · imported by {file.imported_by.length}
                {file.is_entry_point && ' · entry point'}
                {file.parse_error && ' · could not be parsed'}
              </span>
              {file.grade && (
                <span className={`grade grade-${file.grade}`}>{file.grade}</span>
              )}
            </div>
            {file.top_findings.length > 0 && (
              <ul className="file-findings">
                {file.top_findings.map((finding, index) => (
                  <li key={index}>
                    <span className={`badge badge-${finding.severity}`}>
                      {SEVERITIES[finding.severity].label}
                    </span>
                    <span className="line">line {finding.line}</span>{' '}
                    {finding.message}
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>

      <h2>
        Priority problems <span className="count">{findings.length}</span>
      </h2>
      {report.findings_not_explained > 0 && (
        <p className="hint">
          The {report.findings_not_explained} lowest-ranked findings are listed
          without a written explanation. Explaining every one is what costs the
          time and the money, and the worst are the ones worth reading first.
        </p>
      )}
      <ul className="issues">
        {findings.slice(0, 20).map((finding, index) => {
          const explained = report.explanations?.explained_findings?.find(
            (item) => item.path === finding.path && item.line === finding.line
          )
          return (
            <li key={index} className={`issue issue-${finding.severity}`}>
              <div className="issue-header">
                <span className="badge">{SEVERITIES[finding.severity].label}</span>
                <code className="line">
                  {finding.path}:{finding.line}
                </code>
              </div>
              <p className="issue-message">{finding.message}</p>
              {explained ? (
                <>
                  <p className="issue-why">{explained.why_it_matters}</p>
                  <p className="issue-suggestion">{explained.how_to_fix}</p>
                  <p className="issue-learn">You learn: {explained.what_you_learn}</p>
                  {explained.likely_false_positive && (
                    <p className="issue-doubt">
                      Flagged as a likely false positive by the review.
                    </p>
                  )}
                </>
              ) : (
                <p className="issue-suggestion">{finding.suggestion}</p>
              )}
            </li>
          )
        })}
      </ul>

      {report.explanations?.questions_for_the_team?.length > 0 && (
        <>
          <h2>Questions for the team</h2>
          <ul className="questions">
            {report.explanations.questions_for_the_team.map((question, index) => (
              <li key={index}>{question}</li>
            ))}
          </ul>
        </>
      )}

      {report.llm_dropped_claims > 0 && (
        <p className="hint">
          {report.llm_dropped_claims} statement
          {report.llm_dropped_claims === 1 ? '' : 's'} from the review were
          discarded because they referred to code that does not exist.
        </p>
      )}
    </section>
  )
}

function explain(reason) {
  const messages = {
    disabled: 'the AI review was switched off for this run.',
    no_api_key: 'no API key is configured.',
    refusal: 'the model declined to answer for this input.',
    timeout: 'the request timed out.',
    rate_limited: 'the API rate limit was reached.',
    network_error: 'the API could not be reached.',
    server_error: 'the API returned a server error.',
    auth_error: 'the API key was rejected.',
    budget_exceeded: 'this project is too large to review in one request.',
    unparsable_response: 'the response could not be read.',
  }
  return messages[reason] ?? `the review failed (${reason}).`
}

export default ProjectReport
