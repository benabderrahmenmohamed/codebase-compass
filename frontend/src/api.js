// Every call to the backend goes through this file.
// React components do not need to know a server exists.

import { getToken, signOut } from './session'

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

/**
 * The Authorization header, when there is a session.
 *
 * Absent for a guest, which is not an error: the deterministic report
 * needs nobody's permission.
 */
function authHeaders() {
  const token = getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}


async function handle(response) {
  const data = await readJson(response)

  // The token expired, was signed with a rotated secret, or names an
  // account that has been deleted. Whatever the cause, this client is no
  // longer authenticated and holding the dead token would make every
  // subsequent request fail the same way.
  if (response.status === 401) {
    signOut()
    throw new Error(
      (data && data.detail) || 'Your session has ended. Sign in again.'
    )
  }

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
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
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
      headers: authHeaders(),
      credentials: 'include',
    })
  } catch {
    throw new Error(
      'Cannot reach the server. Is the backend running on port 8000?'
    )
  }

  return handle(response)
}


/**
 * Exchange a name and password for a token.
 *
 * Deliberately does NOT send the Authorization header: logging in while
 * already holding a dead token would fail for the wrong reason.
 */
export async function login(name, password) {
  let response
  try {
    response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, password }),
      credentials: 'include',
    })
  } catch {
    throw new Error(
      'Cannot reach the server. Is the backend running on port 8000?'
    )
  }

  const data = await readJson(response)
  if (!response.ok) {
    throw new Error(errorMessage(data, response.status))
  }
  return data
}


/** Who the server thinks we are, and what it will let us do. */
export async function whoAmI() {
  let response
  try {
    response = await fetch(`${API_BASE_URL}/users/me`, {
      headers: authHeaders(),
      credentials: 'include',
    })
  } catch {
    throw new Error(
      'Cannot reach the server. Is the backend running on port 8000?'
    )
  }
  return handle(response)
}
