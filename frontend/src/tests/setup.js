import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, beforeEach, vi } from 'vitest'

// jsdom does not implement Blob.prototype.text, which every browser has had
// since 2019. Without this, readFiles() fails in tests for a reason that
// cannot happen in production.
if (typeof Blob.prototype.text !== 'function') {
  Blob.prototype.text = function text() {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => resolve(reader.result)
      reader.onerror = () => reject(reader.error)
      reader.readAsText(this)
    })
  }
}

// Unmount between tests so one test's DOM cannot be found by the next.
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// No test may reach the network. A test that forgets to stub fetch fails
// loudly here instead of quietly hitting a real server — the same rule the
// backend suite enforces by blocking non-loopback sockets.
beforeEach(() => {
  globalThis.fetch = vi.fn(() => {
    throw new Error('A test tried to use the network. Stub fetch instead.')
  })
})
