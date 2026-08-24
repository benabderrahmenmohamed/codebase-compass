import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import ProjectReport from '../components/ProjectReport'

// The rule this component exists to obey:
//   an empty section must always state its CAUSE.
// "No overview" and "the review could not run" look identical otherwise, and
// showing the second as the first turns missing information into false
// reassurance.

function makeReport(overrides = {}) {
  const category = { score: 20, coverage: 'evaluated', finding_count: 0, method: 'density', density: 0 }
  return {
    project_id: 'p1',
    created_at: '2026-08-24T10:00:00Z',
    scores: {
      security: category,
      readability: category,
      maintainability: category,
      performance: category,
      best_practices: category,
    },
    total_score: 100,
    grade: 'A',
    worst_file: null,
    best_file: null,
    entry_points: ['main.py'],
    external_dependencies: ['fastapi'],
    reading_order: ['main.py'],
    files: [
      {
        path: 'main.py',
        language: 'python',
        lines: 10,
        imports: [],
        imported_by: [],
        is_entry_point: true,
        parse_error: null,
        symbol_count: 2,
        finding_count: 0,
        total_score: 100,
        grade: 'A',
        top_findings: [],
      },
    ],
    findings: [],
    findings_dropped: 0,
    analysis_complete: true,
    semgrep_available: true,
    semgrep_reason: null,
    context_windows_dropped: 0,
    estimated_tokens: 100,
    llm_used: true,
    llm_reason: null,
    llm_retryable: false,
    llm_dropped_claims: 0,
    explanations: null,
    ...overrides,
  }
}

describe('ProjectReport', () => {
  it('shows the total and the grade', () => {
    const { container } = render(<ProjectReport report={makeReport()} />)
    // Scoped to the header: the file list carries its own grade badges too.
    const total = container.querySelector('.total')
    expect(total).toHaveTextContent('100')
    expect(total.querySelector('.grade')).toHaveTextContent('A')
  })

  it('says WHY there is no overview instead of leaving the section blank', () => {
    render(<ProjectReport report={makeReport({ llm_used: false, llm_reason: 'no_api_key' })} />)
    expect(screen.getByText(/no API key is configured/i)).toBeInTheDocument()
  })

  it('offers a retry only when retrying could actually succeed', () => {
    const { rerender } = render(
      <ProjectReport report={makeReport({ llm_reason: 'timeout', llm_retryable: true })} />
    )
    expect(screen.getByText(/Trying again may work/i)).toBeInTheDocument()

    rerender(
      <ProjectReport report={makeReport({ llm_reason: 'auth_error', llm_retryable: false })} />
    )
    expect(screen.queryByText(/Trying again may work/i)).not.toBeInTheDocument()
  })

  it('names an unknown failure reason rather than hiding it', () => {
    render(<ProjectReport report={makeReport({ llm_reason: 'api_error:418' })} />)
    expect(screen.getByText(/api_error:418/)).toBeInTheDocument()
  })

  it('states that the scanner did not run, so findings are missing and not absent', () => {
    render(
      <ProjectReport
        report={makeReport({
          analysis_complete: false,
          semgrep_available: false,
          semgrep_reason: 'semgrep_missing',
        })}
      />
    )
    expect(screen.getByText(/security scanner did not run/i)).toBeInTheDocument()
    expect(screen.getByText(/semgrep_missing/)).toBeInTheDocument()
  })

  // A score of 20 may mean "nothing found" or "nothing looked for". The
  // difference has to be visible or the score is a false claim.
  it('marks a category that was never evaluated', () => {
    const report = makeReport()
    report.scores.security = { ...report.scores.security, coverage: 'not_evaluated' }
    render(<ProjectReport report={report} />)
    expect(screen.getByText(/nothing measured this/i)).toBeInTheDocument()
  })

  it('reports findings that were dropped beyond the cap', () => {
    render(<ProjectReport report={makeReport({ findings_dropped: 240 })} />)
    expect(screen.getByText(/\+240 beyond the cap/)).toBeInTheDocument()
  })

  it('reports model claims discarded for referring to code that does not exist', () => {
    render(<ProjectReport report={makeReport({ llm_dropped_claims: 3 })} />)
    expect(screen.getByText(/3 statements from the review were discarded/i)).toBeInTheDocument()
  })

  it('falls back to the computed reading order when the model explained nothing', () => {
    render(<ProjectReport report={makeReport({ reading_order: ['storage.py', 'main.py'] })} />)
    expect(screen.getByText('storage.py')).toBeInTheDocument()
  })

  it('renders symbol translations when the model supplied them', () => {
    render(
      <ProjectReport
        report={makeReport({
          explanations: {
            overview: 'A demo service.',
            reading_order: [],
            explained_findings: [],
            questions_for_the_team: [],
            symbols_to_clarify: [
              {
                path: 'auth.py',
                line: 8,
                current_name: 'x',
                actually_holds: 'The session expiry timestamp.',
                suggested_name: 'expires_at',
              },
            ],
          },
        })}
      />
    )
    expect(screen.getByText('The session expiry timestamp.')).toBeInTheDocument()
    expect(screen.getByText('expires_at')).toBeInTheDocument()
  })
})
