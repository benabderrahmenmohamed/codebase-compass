import { fireEvent, render, screen, waitFor } from '@testing-library/react'
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

    expect(onAnalyse).toHaveBeenCalledWith(
      { files: [{ path: 'demo/main.py', content: 'print(1)' }] },
      ''
    )
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

// --------------------------------------------------------------------------
// Two sources, never at once
// --------------------------------------------------------------------------

describe('ProjectPicker source selection', () => {
  function typeRepo(container, value) {
    const input = container.querySelector('#repo')
    fireEvent.change(input, { target: { value } })
    return input
  }

  it('offers to analyse a repository once the reference parses', () => {
    const { container } = render(<ProjectPicker onAnalyse={vi.fn()} busy={false} />)
    typeRepo(container, 'https://github.com/acme/widget')

    expect(screen.getByRole('button', { name: /Analyse acme\/widget/ })).toBeInTheDocument()
  })

  it('sends the repository rather than files', () => {
    const onAnalyse = vi.fn()
    const { container } = render(<ProjectPicker onAnalyse={onAnalyse} busy={false} />)
    typeRepo(container, 'acme/widget')
    screen.getByRole('button', { name: /Analyse acme\/widget/ }).click()

    expect(onAnalyse).toHaveBeenCalledWith({ repo: 'acme/widget' }, '')
  })

  it('warns immediately about a host it will not fetch', () => {
    const { container } = render(<ProjectPicker onAnalyse={vi.fn()} busy={false} />)
    typeRepo(container, 'https://gitlab.com/acme/widget')

    expect(screen.getByText(/not a GitHub repository/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Analyse/ })).not.toBeInTheDocument()
  })

  it('names the branch when the URL carries one', () => {
    const { container } = render(<ProjectPicker onAnalyse={vi.fn()} busy={false} />)
    typeRepo(container, 'https://github.com/acme/widget/tree/develop')

    expect(screen.getByText(/on branch/i)).toBeInTheDocument()
    expect(screen.getByText('develop')).toBeInTheDocument()
  })

  // The API refuses a submission carrying both. Rather than let the user
  // build one, the interface makes it impossible to express.
  it('clears a chosen folder when a repository is typed, and says so', async () => {
    const { container } = render(<ProjectPicker onAnalyse={vi.fn()} busy={false} />)
    drop(container.querySelector('.dropzone'), [dirEntry('demo', [fileEntry('a.py')])])
    await waitFor(() => expect(container.querySelector('.plan')).toHaveTextContent('1 file ready'))

    typeRepo(container, 'acme/widget')

    expect(container.querySelector('.plan')).toBeNull()
    expect(screen.getByText(/folder was cleared/i)).toBeInTheDocument()
  })

  it('clears a typed repository when a folder is dropped, and says so', async () => {
    const { container } = render(<ProjectPicker onAnalyse={vi.fn()} busy={false} />)
    typeRepo(container, 'acme/widget')
    drop(container.querySelector('.dropzone'), [dirEntry('demo', [fileEntry('a.py')])])

    await waitFor(() => expect(screen.getByText(/repository was cleared/i)).toBeInTheDocument())
    expect(container.querySelector('#repo')).toHaveValue('')
  })

  it('never offers both sources at the same time', async () => {
    const onAnalyse = vi.fn()
    const { container } = render(<ProjectPicker onAnalyse={onAnalyse} busy={false} />)
    drop(container.querySelector('.dropzone'), [dirEntry('demo', [fileEntry('a.py')])])
    await waitFor(() => container.querySelector('.plan'))
    typeRepo(container, 'acme/widget')

    // Exactly one analyse button, and it is the repository one.
    const buttons = screen.getAllByRole('button', { name: /Analyse/ })
    expect(buttons).toHaveLength(1)
    buttons[0].click()
    expect(onAnalyse).toHaveBeenCalledWith({ repo: 'acme/widget' }, '')
  })

  it('drops the cleared notice once the repository field is emptied again', () => {
    const { container } = render(<ProjectPicker onAnalyse={vi.fn()} busy={false} />)
    typeRepo(container, 'acme/widget')
    typeRepo(container, '')

    expect(screen.queryByText(/cleared/i)).not.toBeInTheDocument()
  })
})

describe('ProjectPicker button wording', () => {
  it('says "1 file", not "1 files"', async () => {
    const { container } = render(<ProjectPicker onAnalyse={vi.fn()} busy={false} />)
    drop(container.querySelector('.dropzone'), [dirEntry('demo', [fileEntry('a.py')])])
    await waitFor(() => screen.getByRole('button', { name: /Analyse/ }))

    expect(screen.getByRole('button', { name: 'Analyse 1 file' })).toBeInTheDocument()
  })

  it('pluralises beyond one', async () => {
    const { container } = render(<ProjectPicker onAnalyse={vi.fn()} busy={false} />)
    drop(container.querySelector('.dropzone'), [
      dirEntry('demo', [fileEntry('a.py'), fileEntry('b.py')]),
    ])
    await waitFor(() => screen.getByRole('button', { name: 'Analyse 2 files' }))
  })
})
