import { beforeEach, describe, expect, it, vi } from 'vitest'
import { can, getToken, getUser, isSignedIn, signIn, signOut } from '../session'

// The session lives in localStorage rather than an HttpOnly cookie. That is
// a trade, not a default: a cookie cannot be read by a script but is sent
// automatically (CSRF); localStorage is readable by a script but is never
// sent automatically (no CSRF). See session.js for the reasoning.

const LOGIN = {
  access_token: 'a.b.c',
  token_type: 'bearer',
  expires_in: 28800,
  name: 'alice',
  role: 'developer',
  permissions: ['submit_project', 'use_llm', 'read_own'],
}

beforeEach(() => {
  window.localStorage.clear()
})

describe('signing in and out', () => {
  it('starts signed out', () => {
    expect(isSignedIn()).toBe(false)
    expect(getUser()).toBeNull()
    expect(getToken()).toBeNull()
  })

  it('keeps the token and the user after signing in', () => {
    signIn(LOGIN)

    expect(getToken()).toBe('a.b.c')
    expect(getUser()).toEqual({
      name: 'alice',
      role: 'developer',
      permissions: ['submit_project', 'use_llm', 'read_own'],
    })
  })

  it('survives a page reload', () => {
    signIn(LOGIN)
    // Nothing is cached in module state, so a fresh read is what a reloaded
    // page sees.
    expect(getUser().name).toBe('alice')
  })

  it('forgets everything on sign out', () => {
    signIn(LOGIN)
    signOut()

    expect(isSignedIn()).toBe(false)
    expect(getUser()).toBeNull()
  })
})

describe('permissions held for rendering', () => {
  it('reports what the SERVER said this role may do', () => {
    signIn(LOGIN)
    expect(can('use_llm')).toBe(true)
    expect(can('manage_users')).toBe(false)
  })

  it('grants nothing when signed out', () => {
    expect(can('use_llm')).toBe(false)
  })
})

describe('storage that refuses to co-operate', () => {
  it('treats an unreadable session as signed out rather than crashing', () => {
    // A private window with site data blocked THROWS rather than returning
    // null. An unreadable session is a signed-out session, not a broken page.
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('SecurityError')
    })

    expect(getToken()).toBeNull()
    expect(getUser()).toBeNull()
    expect(isSignedIn()).toBe(false)
  })

  it('does not throw when writing is refused', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceededError')
    })

    expect(() => signIn(LOGIN)).not.toThrow()
  })

  it('treats a corrupted user record as signed out', () => {
    window.localStorage.setItem('compass_user', 'not json at all')
    expect(getUser()).toBeNull()
  })
})
