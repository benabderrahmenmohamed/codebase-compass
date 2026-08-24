"""Layer 7: assembling the report.

Every layer below produces one piece. This puts them together in the order a
newcomer actually needs, and — just as importantly — records what could NOT
be produced.

The rule the whole file obeys: **an empty section must always state its
cause.** "No security findings" and "the security scanner could not run" look
identical unless the report says which it was, and a tool that quietly
reports the second as the first is worse than no tool.
"""

from datetime import datetime, timezone

from analysis import claude_client, context, findings, scoring, skeleton

# How many findings each file carries in the report before the rest are
# summarised. The full ranked list is available separately.
FINDINGS_PER_FILE = 5


def analyse_project(
    contents: dict[str, str],
    use_llm: bool = True,
    client=None,
) -> dict:
    """Run every layer over a project and return the complete report.

    `use_llm=False` skips the Claude layer entirely — useful for tests, for
    an offline deployment, and for anyone who would rather not spend money.
    The report is smaller without it, never broken.
    """
    collected = findings.collect(contents)
    built = skeleton.build(contents)
    score = scoring.score_project(
        contents, collected.findings, collected.semgrep_available
    )
    payload = context.build_payload(contents, built, collected.findings)

    llm = claude_client.ClaudeResult(None, False, "disabled")
    if use_llm:
        llm = claude_client.analyse(payload, contents, built, client=client)

    findings_by_file: dict[str, list] = {}
    for finding in collected.findings:
        findings_by_file.setdefault(finding.path, []).append(finding)

    file_scores = {file.path: file for file in score.files}

    files = []
    for file in built.files:
        in_file = findings_by_file.get(file.path, [])
        file_score = file_scores.get(file.path)
        files.append(
            {
                "path": file.path,
                "language": file.language,
                "lines": file.lines,
                "imports": built.imports_graph.get(file.path, []),
                "imported_by": built.imported_by.get(file.path, []),
                "is_entry_point": file.is_entry_point,
                "parse_error": file.parse_error,
                "symbol_count": len(file.symbols),
                "finding_count": len(in_file),
                "total_score": file_score.total if file_score else None,
                "grade": file_score.grade if file_score else None,
                "top_findings": [_finding_out(f) for f in in_file[:FINDINGS_PER_FILE]],
            }
        )

    # Worst first: the file a newcomer should be warned about, not the one
    # that happens to sort first alphabetically.
    files.sort(key=lambda file: (file["total_score"] is None, file["total_score"]))

    return {
        "created_at": datetime.now(timezone.utc),
        # --- section 10: health -------------------------------------------
        "scores": {
            name: {
                "score": category.score,
                "coverage": category.coverage,
                "finding_count": category.finding_count,
                "method": category.method,
                "density": category.density,
            }
            for name, category in score.scores.items()
        },
        "total_score": score.total,
        "grade": score.grade,
        "worst_file": score.worst_file,
        "best_file": score.best_file,
        # --- sections 2 and 3: the map and where to start ------------------
        "entry_points": built.entry_points,
        "external_dependencies": built.external_dependencies,
        "reading_order": skeleton.reading_order(built),
        "files": files,
        # --- section 7: what was found ------------------------------------
        "findings": [_finding_out(f) for f in collected.findings],
        "findings_dropped": collected.dropped,
        # --- what could not be done ---------------------------------------
        "analysis_complete": collected.is_complete and payload.is_complete,
        "semgrep_available": collected.semgrep_available,
        "semgrep_reason": collected.semgrep_reason,
        "context_windows_dropped": payload.dropped_windows,
        # Findings below the explanation cap. They are all in `findings`
        # above; the model was simply not asked to write about them.
        "findings_not_explained": payload.findings_not_explained,
        "estimated_tokens": payload.estimated_tokens,
        # --- sections 1, 4, 5, 9: what the model added --------------------
        "llm_used": llm.available,
        "llm_reason": llm.reason,
        "llm_retryable": llm.is_retryable,
        "llm_dropped_claims": llm.dropped_claims,
        "llm_input_tokens": llm.input_tokens,
        "llm_output_tokens": llm.output_tokens,
        "llm_cache_read_tokens": llm.cache_read_tokens,
        "llm_cost_usd": round(llm.estimated_cost_usd, 4),
        "explanations": llm.report.model_dump() if llm.report else None,
    }


def _finding_out(finding) -> dict:
    return {
        "path": finding.path,
        "line": finding.line,
        "severity": finding.severity,
        "category": finding.category,
        "message": finding.message,
        "suggestion": finding.suggestion,
        "source": finding.source,
        "symbol": finding.symbol,
    }
