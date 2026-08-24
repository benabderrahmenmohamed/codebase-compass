import { describe, expect, it } from 'vitest'
import {
  MAX_CHARS_PER_FILE,
  MAX_FILES,
  fromDataTransfer,
  fromFileList,
  planUpload,
  readFiles,
} from '../projectFiles'

// --- helpers -------------------------------------------------------------

function makeFile(name, content = '') {
  return new File([content], name, { type: 'text/plain' })
}

function entry(path, content = 'x') {
  return { file: makeFile(path.split('/').pop(), content), path }
}

/** A fake File System Entries tree, as a dropped folder would expose it. */
function fileEntry(name, content = 'x') {
  return {
    isFile: true,
    isDirectory: false,
    name,
    file: (resolve) => resolve(makeFile(name, content)),
  }
}

function dirEntry(name, children) {
  return {
    isFile: false,
    isDirectory: true,
    name,
    createReader() {
      // Chromium hands back at most 100 entries per readEntries() call, so
      // the fake does the same: code that reads once sees only the first 100.
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

function dataTransfer(entries) {
  return {
    items: entries.map((e) => ({ webkitGetAsEntry: () => e })),
    files: [],
  }
}

// --- planUpload ----------------------------------------------------------

describe('planUpload', () => {
  it('keeps files with an analysable extension', () => {
    const { toSend, skipped } = planUpload([entry('app/main.py')])
    expect(toSend).toHaveLength(1)
    expect(skipped).toHaveLength(0)
  })

  it('skips a dependency folder and says why', () => {
    const { toSend, skipped } = planUpload([entry('node_modules/react/index.js')])
    expect(toSend).toHaveLength(0)
    expect(skipped[0].reason).toBe('ignored_folder')
  })

  it('skips a file whose extension is not analysable', () => {
    const { skipped } = planUpload([entry('README.md')])
    expect(skipped[0].reason).toBe('unsupported_extension')
  })

  it('skips a file with no extension at all', () => {
    const { skipped } = planUpload([entry('Makefile')])
    expect(skipped[0].reason).toBe('unsupported_extension')
  })

  it('skips a file larger than the per-file cap', () => {
    const big = entry('big.py', 'x'.repeat(MAX_CHARS_PER_FILE + 1))
    expect(planUpload([big]).skipped[0].reason).toBe('file_too_large')
  })

  it('normalises Windows separators', () => {
    const { toSend } = planUpload([
      { file: makeFile('main.py'), path: 'app\\routes\\main.py' },
    ])
    expect(toSend[0].path).toBe('app/routes/main.py')
  })

  it('matches the extension case-insensitively', () => {
    expect(planUpload([entry('Main.PY')]).toSend).toHaveLength(1)
  })

  it('never rejects the whole submission because one file was skipped', () => {
    const { toSend, skipped } = planUpload([entry('a.py'), entry('b.md')])
    expect(toSend).toHaveLength(1)
    expect(skipped).toHaveLength(1)
  })
})

// --- readFiles -----------------------------------------------------------

describe('readFiles', () => {
  it('reads the content of each planned file', async () => {
    const { files, totalChars } = await readFiles([
      { file: makeFile('a.py', 'print(1)'), path: 'a.py' },
    ])
    expect(files).toEqual([{ path: 'a.py', content: 'print(1)' }])
    expect(totalChars).toBe(8)
  })

  it('stops at the file-count cap and reports the rest', async () => {
    const planned = Array.from({ length: MAX_FILES + 3 }, (_, i) => ({
      file: makeFile(`f${i}.py`, 'x'),
      path: `f${i}.py`,
    }))
    const { files, skipped } = await readFiles(planned)
    expect(files).toHaveLength(MAX_FILES)
    expect(skipped).toHaveLength(3)
    expect(skipped[0].reason).toBe('too_many_files')
  })

  it('keeps an empty file, because an empty __init__.py still carries structure', async () => {
    const { files } = await readFiles([
      { file: makeFile('__init__.py', ''), path: 'pkg/__init__.py' },
    ])
    expect(files).toHaveLength(1)
  })
})

// --- fromFileList --------------------------------------------------------

describe('fromFileList', () => {
  it('uses webkitRelativePath when the picker supplied one', () => {
    const file = makeFile('main.py')
    Object.defineProperty(file, 'webkitRelativePath', { value: 'backend/main.py' })
    expect(fromFileList([file])[0].path).toBe('backend/main.py')
  })

  it('falls back to the bare name for a plain multi-file selection', () => {
    expect(fromFileList([makeFile('main.py')])[0].path).toBe('main.py')
  })

  it('tolerates an empty selection', () => {
    expect(fromFileList(null)).toEqual([])
  })
})

// --- fromDataTransfer: the dropped-folder path ---------------------------

describe('fromDataTransfer', () => {
  it('walks a dropped folder into paths, which dataTransfer.files cannot do', async () => {
    const tree = dirEntry('backend', [
      fileEntry('main.py'),
      dirEntry('routers', [fileEntry('projects.py')]),
    ])
    const { entries } = await fromDataTransfer(dataTransfer([tree]))
    expect(entries.map((e) => e.path).sort()).toEqual([
      'backend/main.py',
      'backend/routers/projects.py',
    ])
  })

  it('reads past the first 100 children, which readEntries does not do in one call', async () => {
    const many = Array.from({ length: 250 }, (_, i) => fileEntry(`f${i}.py`))
    const { entries } = await fromDataTransfer(dataTransfer([dirEntry('src', many)]))
    expect(entries).toHaveLength(250)
  })

  it('prunes a dependency folder without descending into it', async () => {
    let descended = false
    const nodeModules = {
      isFile: false,
      isDirectory: true,
      name: 'node_modules',
      createReader() {
        descended = true
        return { readEntries: (resolve) => resolve([]) }
      },
    }
    const tree = dirEntry('app', [fileEntry('index.js'), nodeModules])
    const { entries, skipped } = await fromDataTransfer(dataTransfer([tree]))

    expect(descended).toBe(false)
    expect(entries.map((e) => e.path)).toEqual(['app/index.js'])
    expect(skipped[0]).toEqual({ path: 'app/node_modules', reason: 'ignored_folder' })
  })

  it('handles a single dropped file', async () => {
    const { entries } = await fromDataTransfer(dataTransfer([fileEntry('a.py')]))
    expect(entries.map((e) => e.path)).toEqual(['a.py'])
  })

  it('falls back to the flat list when the entries API is unavailable', async () => {
    const { entries } = await fromDataTransfer({
      items: [{}],
      files: [makeFile('a.py')],
    })
    expect(entries.map((e) => e.path)).toEqual(['a.py'])
  })
})
