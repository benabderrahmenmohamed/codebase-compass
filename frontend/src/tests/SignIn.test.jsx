import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import SignIn from '../components/SignIn'
import { getToken, getUser } from '../session'

function respond({ ok = true, status = 200, body = {} }) {
  globalThis.fetch = vi.fn(async () => ({ ok, status, json: async () => body }))
}

const SESSION = {
  access_token: 'a.b.c',
  token_type: 'bearer',
  expires_in: 28800,
  name: 'alice',
  role: 'developer',
  permissions: ['use_llm'],
}

beforeEach(() => {
  window.localStorage.clear()
})

function open() {
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
}

function fill(name, password) {
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: name } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: password } })
}

describe('SignIn', () => {
  // A guest is a supported way to use this tool, not a failed login.
  it('describes a signed-out visitor as a guest', () => {
    render(<SignIn user={null} onChange={vi.fn()} />)
    expect(screen.getByText(/browsing as a guest/i)).toBeInTheDocument()
  })

  it('stores the session on a successful sign in', async () => {
    respond({ body: SESSION })
    const onChange = vi.fn()
    render(<SignIn user={null} onChange={onChange} />)

    open()
    fill('alice', 'a-long-enough-passphrase')
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    await waitFor(() => expect(getToken()).toBe('a.b.c'))
    expect(getUser().role).toBe('developer')
    expect(onChange).toHaveBeenCalled()
  })

  it('sends the credentials to the login endpoint', async () => {
    respond({ body: SESSION })
    render(<SignIn user={null} onChange={vi.fn()} />)

    open()
    fill('alice', 'a-long-enough-passphrase')
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalled())
    const [url, options] = globalThis.fetch.mock.calls[0]
    expect(url).toMatch(/\/auth\/login$/)
    expect(JSON.parse(options.body)).toEqual({
      name: 'alice',
      password: 'a-long-enough-passphrase',
    })
  })

  // The server returns one message for a wrong password and for an unknown
  // user, deliberately. Showing it verbatim preserves that.
  it('shows the failure exactly as the server phrased it', async () => {
    respond({ ok: false, status: 401, body: { detail: 'Those credentials were not accepted.' } })
    render(<SignIn user={null} onChange={vi.fn()} />)

    open()
    fill('alice', 'wrong')
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    await waitFor(() =>
      expect(screen.getByText('Those credentials were not accepted.')).toBeInTheDocument()
    )
    expect(getToken()).toBeNull()
  })

  it('clears the password field after a failed attempt', async () => {
    respond({ ok: false, status: 401, body: { detail: 'nope' } })
    render(<SignIn user={null} onChange={vi.fn()} />)

    open()
    fill('alice', 'wrong')
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    await waitFor(() => expect(screen.getByLabelText('Password')).toHaveValue(''))
  })

  it('shows who is signed in, and their role', () => {
    render(
      <SignIn user={{ name: 'alice', role: 'lead', permissions: [] }} onChange={vi.fn()} />
    )
    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(screen.getByText('lead')).toBeInTheDocument()
  })

  it('signs out', () => {
    window.localStorage.setItem('compass_token', 'a.b.c')
    const onChange = vi.fn()
    render(
      <SignIn user={{ name: 'alice', role: 'lead', permissions: [] }} onChange={onChange} />
    )

    fireEvent.click(screen.getByRole('button', { name: /sign out/i }))

    expect(getToken()).toBeNull()
    expect(onChange).toHaveBeenCalled()
  })

  // Open registration is how a stranger asks for the admin role.
  it('says accounts come from an administrator rather than offering signup', () => {
    render(<SignIn user={null} onChange={vi.fn()} />)
    open()

    expect(screen.getByText(/created by an administrator/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /create account|register|sign up/i })).toBeNull()
  })

  it('says what a guest can still do', () => {
    render(<SignIn user={null} onChange={vi.fn()} />)
    open()
    expect(screen.getByText(/only the AI review needs an account/i)).toBeInTheDocument()
  })
})
