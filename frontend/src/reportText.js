// Turning a report's machine-readable flags into sentences a person reads.
//
// Lives outside the component because a module that exports both a React
// component and a plain function breaks Fast Refresh — and because this
// is logic worth testing on its own, without rendering anything.

/**
 * Every reason this analysis is not complete.
 *
 * This exists because the previous version was a sentence followed by two
 * conditional clauses, and a report could be incomplete for a reason
 * neither clause covered — the finding cap. It then rendered as the bare
 * words "This analysis is incomplete." with no explanation at all, which
 * is precisely the failure the whole project is built to avoid: a partial
 * result that does not say what is missing.
 *
 * The last line is the guard. If the report is incomplete for a reason
 * nobody has thought to name here yet, it says so honestly rather than
 * saying nothing — so this can never again render an empty explanation.
 */
export function incompleteBecause(report) {
  const causes = []

  if (!report.semgrep_available) {
    causes.push(
      `The security scanner did not run (${report.semgrep_reason}), so ` +
        'security findings are missing — not absent.'
    )
  }
  if (report.findings_dropped > 0) {
    causes.push(
      `${report.findings_dropped} findings beyond the reporting cap were ` +
        'counted but not listed; the ones shown are the most serious.'
    )
  }
  if (report.context_windows_dropped > 0) {
    causes.push(
      `${report.context_windows_dropped} lower-severity code windows were ` +
        'omitted to stay within budget.'
    )
  }
  if (report.findings_not_explained > 0) {
    causes.push(
      `${report.findings_not_explained} findings were listed without a ` +
        'written explanation.'
    )
  }

  if (causes.length === 0) {
    causes.push(
      'A layer did not finish, and this page does not yet name which one. ' +
        'The findings shown are real, but they are not all of them.'
    )
  }
  return causes
}
