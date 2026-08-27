// Every call to the backend goes through this file.
// React components do not need to know a server exists.

// On deployment day, this is the only line to change.
const API_BASE_URL = 'http://localhost:8000'

/**
 * Turn FastAPI's error response into a readable sentence.
 * FastAPI returns two different shapes:
 *   404/413 -> detail is a string
 *   422     -> detail is a list of objects { loc, msg, ... }
 */
function errorMessage(data, status) {
  const detail = data?.detail

  if (typeof detail === 'string') {
    return detail
  }
  if (Array.isArray(detail) && detail.length > 0) {
    return detail[0].msg
  }
  return `Error ${status}`
}

/**
 * Read the body as JSON, or return null.
 *
 * Not every failure comes back as JSON: a crash produces an HTML error page,
 * and a proxy in front of the API produces its own. Calling .json() on those
 * throws a parser error, and the user is then shown "Unexpected token '<'"
 * instead of anything about their request.
 */
async function readJson(response) {
  try {
    return await response.json()
  } catch {
    return null
  }
}

async function handle(response) {
  const data = await readJson(response)

  // CAREFUL: fetch does NOT throw on a 404 or a 422. Without this check we
  // would carry on with an error body instead of a report.
  if (!response.ok) {
    throw new Error(errorMessage(data, response.status))
  }
  if (data === null) {
    throw new Error('The server returned a response that could not be read.')
  }
  return data
}

async function request(path, body) {
  let response

  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      // Carries the guest cookie the server sets, so this browser's
      // submissions stay its own. Without it every anonymous visitor
      // shares one identity and sees everybody else's projects.
      credentials: 'include',
    })
  } catch {
    // We only get here when the network itself failed: server down, CORS
    // blocked. fetch does NOT throw on a 404 or a 422.
    throw new Error(
      'Cannot reach the server. Is the backend running on port 8000?'
    )
  }

  return handle(response)
}

/**
 * Send one snippet of code and return the analysis report.
 * Throws an Error if the server refuses the request or is unreachable.
 */
export async function analyzeCode(code, language) {
  // Optional field: we send null when the user typed nothing.
  return request('/analyses', { code, language: language || null })
}

/**
 * Send a whole project, from one of two sources.
 *
 * `source` is either { files: [{ path, content }] } for an uploaded folder,
 * or { repo: "owner/repo" } for a public GitHub repository the server
 * fetches itself. Never both: the API refuses a submission naming two
 * sources, because one report cannot describe two projects.
 *
 * Returns which files were accepted and which were skipped, and why.
 */
export async function submitProject(source, name) {
  return request('/projects', { name: name || null, ...source })
}

/**
 * Run the analysis on a project that has already been submitted.
 *
 * Submission and analysis are two calls on purpose: the first returns
 * instantly, so the user sees what was accepted while the second one works.
 *
 * Pass useLlm=false for the deterministic report only — no API call, no cost.
 */
export async function analyseProject(projectId, useLlm = true) {
  const query = useLlm ? '' : '?use_llm=false'
  let response

  try {
    response = await fetch(`${API_BASE_URL}/projects/${projectId}/analysis${query}`, {
      method: 'POST',
      credentials: 'include',
    })
  } catch {
    throw new Error(
      'Cannot reach the server. Is the backend running on port 8000?'
    )
  }

  return handle(response)
}
