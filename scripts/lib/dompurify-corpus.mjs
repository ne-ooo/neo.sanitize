import { createHash } from 'node:crypto'

const MODULE_PREFIX = 'export default'

export function getSHA256(value) {
  return createHash('sha256').update(value).digest('hex')
}

/** Parse the static JSON-compatible fixture export without executing it. */
export function parseDOMPurifyFixtures(source) {
  const trimmed = source.trim()
  if (!trimmed.startsWith(MODULE_PREFIX)) {
    throw new TypeError('The DOMPurify fixture must start with export default.')
  }

  let expression = trimmed.slice(MODULE_PREFIX.length).trim()
  if (!expression.endsWith(';')) {
    throw new TypeError('The DOMPurify fixture must end with a semicolon.')
  }

  expression = expression.slice(0, -1).trim().replace(/,\s*\]$/u, ']')

  let fixtures
  try {
    fixtures = JSON.parse(expression)
  } catch (cause) {
    throw new TypeError(
      'The DOMPurify fixture must contain one static JSON-compatible array.',
      { cause }
    )
  }

  if (!Array.isArray(fixtures)) {
    throw new TypeError('The DOMPurify fixture export must be an array.')
  }

  for (const [index, fixture] of fixtures.entries()) {
    if (
      typeof fixture !== 'object' ||
      fixture === null ||
      typeof fixture.payload !== 'string'
    ) {
      throw new TypeError(`Invalid DOMPurify fixture at index ${index}.`)
    }
  }

  return fixtures
}

export function createDOMPurifyCorpus({
  fixtures,
  version,
  commit,
  sha256,
}) {
  const cases = fixtures.map((fixture, index) => ({
    id: `dompurify-${String(index + 1).padStart(3, '0')}`,
    title:
      typeof fixture.title === 'string'
        ? fixture.title
        : `Untitled fixture ${index + 1}`,
    payload: fixture.payload,
  }))

  return {
    source: {
      project: 'DOMPurify',
      repository: 'https://github.com/cure53/DOMPurify',
      file: 'test/fixtures/expect.mjs',
      version,
      commit,
      sha256,
      license: 'Apache-2.0',
    },
    modification:
      'neo.sanitize retained fixture payloads and available titles. It added stable labels for untitled fixtures, removed DOMPurify-specific expected output, and checks neo.sanitize security invariants.',
    caseCount: cases.length,
    cases,
  }
}
