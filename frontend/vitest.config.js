import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// The React Compiler babel plugin from vite.config.js is deliberately NOT
// reused here: it is a build-time optimisation, and running it inside the
// test transform leaves JSX on the classic runtime, which fails with
// "React is not defined". Tests compile JSX with the automatic runtime,
// which is what the browser bundle ends up using anyway.
//
// Tests run in jsdom and never touch the network: fetch is stubbed. This
// mirrors the backend rule — the whole suite must pass offline, with no
// server and no API key.
export default defineConfig({
  plugins: [react()],
  esbuild: {
    jsx: 'automatic',
    jsxImportSource: 'react',
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/tests/setup.js'],
    include: ['src/**/*.test.{js,jsx}'],
  },
})
