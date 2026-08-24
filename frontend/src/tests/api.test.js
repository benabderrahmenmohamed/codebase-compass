import { describe, expect, it, vi } from 'vitest'
import { analyseProject, analyzeCode, submitProject } from '../api'

function respond({ ok = true, status = 200, body = {}, raw = null }) {
  globalThis.fetch = vi.fn(async () => ({
    ok,
    status,
    json: async () => {
      if (raw !== null) throw new SyntaxError(`Unexpected token '<'`)
      return body
    },
  }))
}

describe('analyzeCode', () => {
  it('returns the report on success', async () => {
    respond({ body: { total_score: 92 } })
    await expect(analyzeCode('print(1)', 'python')).resolves.toEqual({ total_score: 92 })
  })

  it('sends null rather than an empty string when no language was typed', async () => {
    respond({ body: {} })
    await analyzeCode('print(1)', '')
    const sent = JSON.parse(globalThis.fetch.mock.calls[0][1].body)
    expect(sent.language).toBeNull()
  })

  it('turns a 422 validation list into the first message', async () => {
    respond({
      ok: false,
      status: 422,
      body: { detail: [{ loc: ['body', 'code'], msg: 'code cannot be empty' }] },
    })
    await expect(analyzeCode('   ')).rejects.toThrow('code cannot be empty')
  })

  it('turns a string detail into the message', async () => {
    respond({ ok: false, status: 404, body: { detail: 'Analysis not found' } })
    await expect(analyzeCode('x')).rejects.toThrow('Analysis not found')
  })

  it('falls back to the status code when there is no detail', async () => {
    respond({ ok: false, status: 500, body: {} })
    await expect(analyzeCode('x')).rejects.toThrow('Error 500')
  })

  it('explains an unreachable server instead of leaking the fetch error', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new TypeError('Failed to fetch')
    })
    await expect(analyzeCode('x')).rejects.toThrow(/backend running on port 8000/)
  })

  // The bug this guards: an HTML error page made .json() throw, and the user
  // was shown "Unexpected token '<'" instead of anything about the failure.
  it('does not leak a JSON parser error when the body is not JSON', async () => {
    respond({ ok: false, status: 502, raw: '<html>Bad Gateway</html>' })
    const error = await analyzeCode('x').catch((e) => e)
    expect(error.message).toBe('Error 502')
    expect(error.message).not.toMatch(/Unexpected token/)
  })

  it('rejects rather than returning null when a 200 body is unreadable', async () => {
    respond({ ok: true, status: 200, raw: 'not json' })
    await expect(analyzeCode('x')).rejects.toThrow(/could not be read/)
  })
})

describe('submitProject', () => {
  it('posts the files and the optional name', async () => {
    respond({ body: { project_id: 'p1' } })
    await submitProject({ files: [{ path: 'a.py', content: 'x' }] }, 'demo')
    const sent = JSON.parse(globalThis.fetch.mock.calls[0][1].body)
    expect(sent).toEqual({ name: 'demo', files: [{ path: 'a.py', content: 'x' }] })
  })

  it('posts a repository reference instead of files', async () => {
    respond({ body: { project_id: 'p1' } })
    await submitProject({ repo: 'acme/widget' }, null)
    const sent = JSON.parse(globalThis.fetch.mock.calls[0][1].body)
    expect(sent).toEqual({ name: null, repo: 'acme/widget' })
  })

  it('surfaces the 404 for a repository that is missing or private', async () => {
    respond({ ok: false, status: 404, body: { detail: 'No such public repository.' } })
    await expect(submitProject({ repo: 'acme/nope' }, null)).rejects.toThrow(
      'No such public repository.'
    )
  })

  it('surfaces the 429 when GitHub rate-limits the fetch', async () => {
    respond({ ok: false, status: 429, body: { detail: "GitHub's rate limit was reached." } })
    await expect(submitProject({ repo: 'acme/widget' }, null)).rejects.toThrow(/rate limit/)
  })

  it('surfaces the 413 limit message', async () => {
    respond({ ok: false, status: 413, body: { detail: 'Too many files' } })
    await expect(submitProject({ files: [] }, null)).rejects.toThrow('Too many files')
  })
})

describe('analyseProject', () => {
  it('asks for the deterministic report only when the LLM is switched off', async () => {
    respond({ body: {} })
    await analyseProject('p1', false)
    expect(globalThis.fetch.mock.calls[0][0]).toMatch(/\/projects\/p1\/analysis\?use_llm=false$/)
  })

  it('asks for the full report by default', async () => {
    respond({ body: {} })
    await analyseProject('p1')
    expect(globalThis.fetch.mock.calls[0][0]).toMatch(/\/projects\/p1\/analysis$/)
  })

  it('explains an unreachable server', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new TypeError('Failed to fetch')
    })
    await expect(analyseProject('p1')).rejects.toThrow(/backend running on port 8000/)
  })
})
