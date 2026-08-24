import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import ProjectPicker from '../components/ProjectPicker'
import { formatChars } from '../projectFiles'

// A dropped FOLDER is only reachable through the File System Entries API.
// dataTransfer.files contains one extension-less entry that reads as empty,
// so a picker that reads .files reports "0 files ready" on a dropzone that
// says "Drop a folder here".

function fileEntry(name, content = 'x') {
  return {
    isFile: true,
    isDirectory: false,
    name,
    file: (resolve) => resolve(new File([content], name, { type: 'text/plain' })),
  }
}

function dirEntry(name, children) {
  return {
    isFile: false,
    isDirectory: true,
    name,
    createReader() {
      let cursor = 0
      return {
        readEntries(resolve) {
          const batch = children.slice(cursor, cursor + 100)
          cursor += batch.length
          resolve(batch)
        },
      }
    },
  }
}

function drop(zone, entries) {
  const event = new Event('drop', { bubbles: true, cancelable: true })
  Object.defineProperty(event, 'dataTransfer', {
    value: { items: entries.map((e) => ({ webkitGetAsEntry: () => e })), files: [] },
  })
  zone.dispatchEvent(event)
}

describe('formatChars', () => {
  it('shows exact characters below a thousand rather than "0 k"', () => {
    expect(formatChars(120)).toBe('120 characters')
  })

  it('rounds to thousands above that', () => {
    expect(formatChars(12_400)).toBe('12 k characters')
  })
})

describe('ProjectPicker drop handling', () => {
  it('reads a dropped folder into files', async () => {
    const { container } = render(<ProjectPicker onAnalyse={vi.fn()} busy={false} />)
    drop(
      container.querySelector('.dropzone'),
      [dirEntry('demo', [fileEntry('main.py'), dirEntry('routers', [fileEntry('p.py')])])]
    )
    // The summary is split across <strong> elements, so match the container.
    await waitFor(() =>
      expect(container.querySelector('.plan')).toHaveTextContent('2 files ready')
    )
  })

  it('hands the analyse button the files with their full paths', async () => {
    const onAnalyse = vi.fn()
    const { container } = render(<ProjectPicker onAnalyse={onAnalyse} busy={false} />)
    drop(container.querySelector('.dropzone'), [dirEntry('demo', [fileEntry('main.py', 'print(1)')])])

    await waitFor(() => screen.getByRole('button', { name: /Analyse 1 file/ }))
    screen.getByRole('button', { name: /Analyse 1 file/ }).click()

    expect(onAnalyse).toHaveBeenCalledWith([{ path: 'demo/main.py', content: 'print(1)' }], '')
  })

  it('reports a pruned dependency folder instead of dropping it silently', async () => {
    const { container } = render(<ProjectPicker onAnalyse={vi.fn()} busy={false} />)
    drop(
      container.querySelector('.dropzone'),
      [dirEntry('demo', [fileEntry('a.py'), dirEntry('node_modules', [fileEntry('r.js')])])]
    )
    await waitFor(() =>
      expect(container.querySelector('.plan')).toHaveTextContent('1 skipped of 2 picked')
    )
    expect(screen.getByText(/ignored folder/)).toBeInTheDocument()
  })

  // Without this, a rejected promise vanished and the user saw the spinner
  // stop with no result and no explanation.
  it('shows an error when the folder cannot be read', async () => {
    const broken = {
      isFile: true,
      isDirectory: false,
      name: 'a.py',
      file: (_resolve, reject) => reject(new Error('Permission denied')),
    }
    const { container } = render(<ProjectPicker onAnalyse={vi.fn()} busy={false} />)
    drop(container.querySelector('.dropzone'), [broken])

    await waitFor(() => expect(screen.getByText(/Permission denied/)).toBeInTheDocument())
    expect(screen.queryByText(/files ready/)).not.toBeInTheDocument()
  })

  it('disables the analyse button while an analysis is running', async () => {
    const { container } = render(<ProjectPicker onAnalyse={vi.fn()} busy />)
    drop(container.querySelector('.dropzone'), [dirEntry('demo', [fileEntry('a.py')])])
    await waitFor(() => expect(screen.getByRole('button', { name: /Analysing/ })).toBeDisabled())
  })
})
