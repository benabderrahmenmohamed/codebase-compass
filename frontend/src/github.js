// Recognising a GitHub repository reference, in the browser.
//
// This mirrors backend/analysis/github_source.py. Like the file filtering in
// projectFiles.js, it is a COURTESY, not a security boundary: it tells the
// user immediately that "https://gitlab.com/a/b" will not work, instead of
// making them wait for a round trip to find out. The server parses the
// reference again and refuses anything that is not a GitHub repository,
// because what the browser sends is data, not truth.

const OWNER = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})'
const REPO = '[A-Za-z0-9._-]{1,100}'

// Every alternative anchors the host with ^, so a URL that merely CONTAINS
// "github.com" — "https://evil.com/github.com/a/b" — cannot match.
const FORMS = [
  new RegExp(`^(?:https?://)?(?:www\\.)?github\\.com/(${OWNER})/(${REPO}?)(?:\\.git)?/tree/([^/\\s]+)/?$`),
  new RegExp(`^(?:https?://)?(?:www\\.)?github\\.com/(${OWNER})/(${REPO}?)(?:\\.git)?/?$`),
  new RegExp(`^git@github\\.com:(${OWNER})/(${REPO}?)(?:\\.git)?/?$`),
  new RegExp(`^(${OWNER})/(${REPO}?)(?:\\.git)?/?$`),
]

/**
 * Parse a reference into { owner, repo, ref }, or return null.
 *
 * Returns null for anything that is not a GitHub repository, including
 * URLs on other hosts and anything pointing at a local address.
 */
export function parseRepoReference(text) {
  if (!text) return null
  const trimmed = text.trim()

  for (const form of FORMS) {
    const match = form.exec(trimmed)
    if (match) {
      const [, owner, rawRepo, ref] = match
      const repo = rawRepo.endsWith('.git') ? rawRepo.slice(0, -4) : rawRepo
      if (!repo) return null
      return { owner, repo, ref: ref ?? null }
    }
  }
  return null
}

/** "acme/widget", for display. */
export function repoSlug(reference) {
  const parsed = parseRepoReference(reference)
  return parsed ? `${parsed.owner}/${parsed.repo}` : null
}
