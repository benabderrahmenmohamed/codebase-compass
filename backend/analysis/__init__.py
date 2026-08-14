"""The analysis engine, in independent layers.

  ingestion      : layer 0  — filter, bound and validate a submitted project
  semgrep_runner : layer 1a — syntax analysis (security, best practices)
  metrics        : layer 1b — measurements (readability, maintainability, perf)
  findings       : normalising and ranking findings from both sources
  context        : selecting the code sent to the LLM
  scoring        : computing the scores
  claude_client  : the call to Claude

Only claude_client costs money; every other layer runs offline and is
testable without a network.
"""
