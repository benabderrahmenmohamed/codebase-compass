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

function relativePath(file) {
  // The folder picker fills webkitRelativePath; a plain drag-and-drop does not.
  return (file.webkitRelativePath || file.name).replace(/\\/g, '/')
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
 * Decide what to send before reading a single byte.
 *
 * Returns { toSend, skipped } where skipped explains each omission, so the
 * user can see that node_modules was dropped rather than wonder why the
 * report looks thin.
 */
export function planUpload(fileList) {
  const toSend = []
  const skipped = []

  for (const file of Array.from(fileList)) {
    const path = relativePath(file)

    if (isIgnored(path)) {
      skipped.push({ path, reason: 'ignored_folder' })
    } else if (!hasAllowedExtension(path)) {
      skipped.push({ path, reason: 'unsupported_extension' })
    } else if (file.size > MAX_CHARS_PER_FILE) {
      skipped.push({ path, reason: 'file_too_large' })
    } else {
      toSend.push({ file, path })
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
