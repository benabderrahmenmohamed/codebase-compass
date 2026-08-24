import { describe, expect, it } from 'vitest'
import { parseRepoReference, repoSlug } from '../github'

// This mirrors backend/analysis/github_source.py. If the two ever disagree,
// the browser accepts something the server rejects — which shows up as a
// confusing round trip rather than an immediate, local explanation.

describe('parseRepoReference', () => {
  it.each([
    ['owner/repo', 'owner', 'repo', null],
    ['https://github.com/owner/repo', 'owner', 'repo', null],
    ['http://github.com/owner/repo', 'owner', 'repo', null],
    ['https://www.github.com/owner/repo', 'owner', 'repo', null],
    ['https://github.com/owner/repo/', 'owner', 'repo', null],
    ['https://github.com/owner/repo.git', 'owner', 'repo', null],
    ['github.com/owner/repo', 'owner', 'repo', null],
    ['git@github.com:owner/repo.git', 'owner', 'repo', null],
    ['https://github.com/owner/repo/tree/develop', 'owner', 'repo', 'develop'],
    ['  owner/repo  ', 'owner', 'repo', null],
    ['owner/repo.with.dots', 'owner', 'repo.with.dots', null],
  ])('accepts %s', (input, owner, repo, ref) => {
    expect(parseRepoReference(input)).toEqual({ owner, repo, ref })
  })

  // Each of these is why the server builds its own URL rather than
  // requesting the one it was handed.
  it.each([
    'http://localhost:8000/admin',
    'http://127.0.0.1/',
    'http://169.254.169.254/latest/meta-data/',
    'https://evil.com/github.com/owner/repo',
    'https://github.com.evil.com/owner/repo',
    'https://gitlab.com/owner/repo',
    'https://bitbucket.org/owner/repo',
    'file:///etc/passwd',
    'not a repository',
    '',
    '   ',
    '/',
    'owner/',
    '/repo',
  ])('refuses %s', (hostile) => {
    expect(parseRepoReference(hostile)).toBeNull()
  })

  it('tolerates a null input', () => {
    expect(parseRepoReference(null)).toBeNull()
    expect(parseRepoReference(undefined)).toBeNull()
  })
})

describe('repoSlug', () => {
  it('reduces a full URL to owner/repo', () => {
    expect(repoSlug('https://github.com/acme/widget/tree/main')).toBe('acme/widget')
  })

  it('returns null for something that is not a repository', () => {
    expect(repoSlug('https://gitlab.com/a/b')).toBeNull()
  })
})
