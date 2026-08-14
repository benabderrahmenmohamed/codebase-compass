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

async function request(path, body) {
  let response

  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  } catch {
    // We only get here when the network itself failed: server down, CORS
    // blocked. fetch does NOT throw on a 404 or a 422.
    throw new Error(
      'Cannot reach the server. Is the backend running on port 8000?'
    )
  }

  const data = await response.json()

  // CAREFUL: fetch does NOT throw on a 404 or a 422. Without this check we
  // would carry on with an error body instead of a report.
  if (!response.ok) {
    throw new Error(errorMessage(data, response.status))
  }

  return data
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
 * Send a whole project: a list of { path, content }.
 * Returns which files were accepted and which were skipped, and why.
 */
export async function submitProject(files, name) {
  return request('/projects', { name: name || null, files })
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
    })
  } catch {
    throw new Error(
      'Cannot reach the server. Is the backend running on port 8000?'
    )
  }

  const data = await response.json()
  if (!response.ok) {
    throw new Error(errorMessage(data, response.status))
  }
  return data
}
