// Holding the signed-in session, in the browser.
//
// **Where the token lives, and the trade that was made.**
// It is kept in localStorage and sent as an Authorization header. The
// alternative is an HttpOnly cookie, and neither option is free:
//
//   * A cookie cannot be read by page scripts, so an XSS flaw cannot steal
//     it — but the browser attaches it to every request automatically,
//     which is what makes CSRF possible and means a token must be paired
//     with a CSRF defence.
//   * localStorage is readable by any script that runs on the page, so an
//     XSS flaw does expose the token — but nothing is ever sent
//     automatically, so CSRF does not apply.
//
// The second is chosen because the API is a separate origin consumed by a
// single-page app, where explicit headers are the natural fit. It is
// written down rather than assumed, because "we used localStorage" is a
// decision a reviewer is entitled to question.
//
// The guest cookie is unaffected: it identifies an anonymous visitor and
// carries no authority, so it stays HttpOnly.

const TOKEN_KEY = 'compass_token'
const USER_KEY = 'compass_user'

/**
 * Read a value, tolerating a browser that refuses storage.
 *
 * localStorage throws rather than returning null in a private window with
 * site data blocked. An unreadable session is a signed-out session, not a
 * crashed page.
 */
function read(key) {
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null
  }
}

function write(key, value) {
  try {
    if (value === null) window.localStorage.removeItem(key)
    else window.localStorage.setItem(key, value)
  } catch {
    // Storage refused. The session then lasts as long as the page, which
    // is worse but not broken.
  }
}

export function getToken() {
  return read(TOKEN_KEY)
}

/**
 * The signed-in user, or null.
 *
 * Name, role and permissions come from the LOGIN RESPONSE, not from
 * decoding the token in the browser. Decoding it here would mean reading
 * claims this client cannot verify, and a habit of trusting unverified
 * claims is how a role check ends up on the wrong side of the network.
 * The server decides; this is a copy for rendering.
 */
export function getUser() {
  const raw = read(USER_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw)
  } catch {
    // Corrupted or hand-edited. Treated as signed out.
    return null
  }
}

export function signIn(loginResponse) {
  write(TOKEN_KEY, loginResponse.access_token)
  write(
    USER_KEY,
    JSON.stringify({
      name: loginResponse.name,
      role: loginResponse.role,
      permissions: loginResponse.permissions || [],
    })
  )
}

/**
 * Forget the session.
 *
 * This is all a client can do. A stateless token cannot be withdrawn, so
 * the token stays valid until it expires — discarding it locally is not
 * revocation, and the server has no /auth/logout precisely because it
 * could not honour one.
 */
export function signOut() {
  write(TOKEN_KEY, null)
  write(USER_KEY, null)
}

export function isSignedIn() {
  return getToken() !== null
}

export function can(permission) {
  const user = getUser()
  return Boolean(user && user.permissions.includes(permission))
}
