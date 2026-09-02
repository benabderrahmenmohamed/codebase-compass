import { useState } from 'react'
import { login } from '../api'
import { signIn, signOut } from '../session'

// Signing in, and showing who is signed in.
//
// Deliberately small. Signing in is not the point of this tool — the
// deterministic report works for anyone with no account at all — so the
// form stays out of the way until somebody wants the paid layer or their
// own history.
//
// There is no "create an account" link. Registration is open by default in
// most tutorials and the first thing a stranger would do is ask for the
// admin role; accounts are created by an administrator instead. Saying so
// beats a button that answers 403.

function SignIn({ user, onChange }) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [failed, setFailed] = useState(null)

  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setFailed(null)
    try {
      const session = await login(name.trim(), password)
      signIn(session)
      setOpen(false)
      setName('')
      setPassword('')
      onChange()
    } catch (error) {
      // The server returns one message for a wrong password and for an
      // unknown user, on purpose. Showing it verbatim keeps that property
      // instead of guessing at something more specific.
      setFailed(error.message)
    } finally {
      // Cleared even on success, so a second attempt is never blocked by
      // a spinner left running.
      setBusy(false)
      setPassword('')
    }
  }

  if (user && user.role !== 'guest') {
    return (
      <div className="session">
        <span className="session-who">
          <strong>{user.name}</strong>
          <span className="session-role">{user.role}</span>
        </span>
        <button
          type="button"
          className="link"
          onClick={() => {
            signOut()
            onChange()
          }}
        >
          Sign out
        </button>
      </div>
    )
  }

  return (
    <div className="session">
      {!open ? (
        <>
          <span className="session-who">
            {/* Not "not signed in": a guest is a supported way to use this,
                not a failure to authenticate. */}
            <span className="session-role">browsing as a guest</span>
          </span>
          <button type="button" className="link" onClick={() => setOpen(true)}>
            Sign in
          </button>
        </>
      ) : (
        <form className="signin" onSubmit={submit}>
          <input
            aria-label="Name"
            placeholder="name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoComplete="username"
          />
          <input
            aria-label="Password"
            type="password"
            placeholder="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
          <button type="submit" disabled={busy || !name.trim() || !password}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
          <button
            type="button"
            className="link"
            onClick={() => {
              setOpen(false)
              setFailed(null)
              setPassword('')
            }}
          >
            Cancel
          </button>
          {failed && <p className="error signin-error">{failed}</p>}
          <p className="hint signin-hint">
            Accounts are created by an administrator. Without one you can
            still map a project and read its findings — only the AI review
            needs an account, because it costs money to run.
          </p>
        </form>
      )}
    </div>
  )
}

export default SignIn
