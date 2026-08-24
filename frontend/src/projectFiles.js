// Filtering a picked folder, in the browser.
//
// This mirrors the server's rules so the user is not made to upload 40,000
// files from node_modules before being told they were ignored. It is a
// COURTESY, not a security boundary: the server re-validates everything,
// because anything the browser sends is data, not truth.

export const ALLOWED_EXTENSIONS = [
  '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', '.go', '.rb',
]

export const IGNORED_FOLDERS = [
  'node_modules', 'venv', '.venv', 'env', '.git', 'dist', 'build',
  'target', 'vendor', '__pycache__', '.pytest_cache', '.tox', '.next',
  'site-packages', 'coverage',
]

export const MAX_FILES = 200
export const MAX_CHARS_PER_FILE = 50_000
export const MAX_CHARS_TOTAL = 2_000_000

// The server refuses more than 5000 submitted entries, so there is no reason
// to walk further than that. Without a bound, dropping a home directory would
// freeze the tab.
export const MAX_WALK_ENTRIES = 5000

function normalise(path) {
  return path.replace(/\\/g, '/')
}

/**
 * Size for display.
 *
 * Rounding straight to thousands showed "0 k characters" for a small but
 * perfectly valid project, which reads as "nothing was read".
 */
export function formatChars(total) {
  if (total < 1000) return `${total} characters`
  return `${Math.round(total / 1000)} k characters`
}

function isIgnored(path) {
  const folders = path.split('/').slice(0, -1)
  return folders.some((folder) => IGNORED_FOLDERS.includes(folder))
}

function hasAllowedExtension(path) {
  const name = path.split('/').pop()
  if (!name.includes('.')) return false
  return ALLOWED_EXTENSIONS.includes('.' + name.split('.').pop().toLowerCase())
}

/**
 * Entries from the folder PICKER.
 *
 * The picker fills webkitRelativePath ("backend/main.py"); a plain multi-file
 * selection does not, so we fall back to the bare name.
 */
export function fromFileList(fileList) {
  return Array.from(fileList ?? []).map((file) => ({
    file,
    path: normalise(file.webkitRelativePath || file.name),
  }))
}

/**
 * Read a directory fully.
 *
 * readEntries() returns AT MOST 100 entries per call in Chromium and says
 * nothing about it — you must keep calling until it hands back an empty
 * batch. Reading once is the single most common bug in folder-drop code: it
 * silently truncates every directory to its first 100 children.
 */
function readAllEntries(reader) {
  return new Promise((resolve, reject) => {
    const found = []
    const readBatch = () => {
      reader.readEntries((batch) => {
        if (batch.length === 0) {
          resolve(found)
          return
        }
        found.push(...batch)
        readBatch()
      }, reject)
    }
    readBatch()
  })
}

async function walk(entry, prefix, found, skipped) {
  if (found.length >= MAX_WALK_ENTRIES) return

  if (entry.isFile) {
    const file = await new Promise((resolve, reject) => entry.file(resolve, reject))
    found.push({ file, path: prefix + entry.name })
    return
  }

  if (entry.isDirectory) {
    // Prune before descending. Walking node_modules only to throw the result
    // away would take longer than the analysis itself, and reporting 40,000
    // skipped files is not a message anybody reads.
    if (IGNORED_FOLDERS.includes(entry.name)) {
      skipped.push({ path: prefix + entry.name, reason: 'ignored_folder' })
      return
    }
    const children = await readAllEntries(entry.createReader())
    for (const child of children) {
      await walk(child, `${prefix + entry.name}/`, found, skipped)
    }
  }
}

/**
 * Entries from a DROP.
 *
 * dataTransfer.files cannot represent a directory: dropping a folder puts one
 * extension-less entry in it that reads as an empty file. webkitGetAsEntry is
 * the only way to see the tree.
 *
 * The entries must be taken SYNCHRONOUSLY, before the first await — a
 * DataTransfer is emptied as soon as the drop handler returns, so awaiting
 * first and reading second gets you nothing.
 */
export async function fromDataTransfer(dataTransfer) {
  const items = Array.from(dataTransfer?.items ?? [])
  const entries = items
    .map((item) => (item.webkitGetAsEntry ? item.webkitGetAsEntry() : null))
    .filter(Boolean)

  // No File System Entries API: fall back to the flat list. Plain files still
  // work; folders cannot, and there is nothing we can do about that here.
  if (entries.length === 0) {
    return { entries: fromFileList(dataTransfer?.files), skipped: [] }
  }

  const found = []
  const skipped = []
  for (const entry of entries) {
    await walk(entry, '', found, skipped)
  }

  if (found.length >= MAX_WALK_ENTRIES) {
    skipped.push({ path: `beyond ${MAX_WALK_ENTRIES} entries`, reason: 'too_many_files' })
  }

  return { entries: found, skipped }
}

/**
 * Decide what to send before reading a single byte.
 *
 * Takes the { file, path } entries produced by fromFileList or
 * fromDataTransfer. Returns { toSend, skipped } where skipped explains each
 * omission, so the user can see that node_modules was dropped rather than
 * wonder why the report looks thin.
 */
export function planUpload(entries) {
  const toSend = []
  const skipped = []

  for (const entry of entries) {
    const path = normalise(entry.path)

    if (isIgnored(path)) {
      skipped.push({ path, reason: 'ignored_folder' })
    } else if (!hasAllowedExtension(path)) {
      skipped.push({ path, reason: 'unsupported_extension' })
    } else if (entry.file.size > MAX_CHARS_PER_FILE) {
      skipped.push({ path, reason: 'file_too_large' })
    } else {
      toSend.push({ file: entry.file, path })
    }
  }

  return { toSend, skipped }
}

/**
 * Read the planned files into { path, content }, stopping at the limits.
 *
 * Reading happens after planning so we never load a 200 MB binary into
 * memory just to discard it.
 */
export async function readFiles(planned) {
  const files = []
  const skipped = []
  let totalChars = 0

  for (const { file, path } of planned) {
    if (files.length >= MAX_FILES) {
      skipped.push({ path, reason: 'too_many_files' })
      continue
    }

    const content = await file.text()

    if (totalChars + content.length > MAX_CHARS_TOTAL) {
      skipped.push({ path, reason: 'project_too_large' })
      continue
    }

    totalChars += content.length
    files.push({ path, content })
  }

  return { files, skipped, totalChars }
}
