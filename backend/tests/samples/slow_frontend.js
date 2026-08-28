// Performance rules for JavaScript.

export async function loadAll(ids) {
  // Each await waits for the previous one: serial, not parallel.
  const results = []
  for (const id of ids) {
    const response = await fetch(`/api/items/${id}`)
    results.push(response)
  }
  return results
}

export function paint(rows) {
  // The document is searched again on every iteration.
  for (const row of rows) {
    const target = document.querySelector('#output')
    target.textContent = row
  }
}
