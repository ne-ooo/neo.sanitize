import { readFile, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const SOURCE_COMMIT = '1a49d19d1f57f67e263a3c6213faf7b4e9db8d7a'
const SOURCE_VERSION = '3.4.14'
const SOURCE_SHA256 = '1c8f8dad1874fcd375665070a8e2be8e011b63a6d6b2ce27ab08585e324eef75'
const sourcePath = process.argv[2]
const outputPath = process.argv[3] ?? 'test/corpus/dompurify-v3.4.14.json'

if (!sourcePath) {
  throw new Error(
    'Usage: node scripts/import-dompurify-corpus.mjs <expect.mjs> [output.json]'
  )
}

const absoluteSource = resolve(sourcePath)
const source = await readFile(absoluteSource, 'utf8')
const sourceSHA256 = createHash('sha256').update(source).digest('hex')
if (sourceSHA256 !== SOURCE_SHA256) {
  throw new Error(
    `The DOMPurify fixture checksum did not match commit ${SOURCE_COMMIT}.`
  )
}
const imported = await import(pathToFileURL(absoluteSource).href)
const fixtures = imported.default

if (!Array.isArray(fixtures)) {
  throw new TypeError('The DOMPurify fixture module must have a default array export.')
}

const cases = fixtures.map((fixture, index) => {
  if (
    typeof fixture !== 'object' ||
    fixture === null ||
    typeof fixture.payload !== 'string'
  ) {
    throw new TypeError(`Invalid DOMPurify fixture at index ${index}.`)
  }

  return {
    id: `dompurify-${String(index + 1).padStart(3, '0')}`,
    title:
      typeof fixture.title === 'string'
        ? fixture.title
        : `Untitled fixture ${index + 1}`,
    payload: fixture.payload,
  }
})

const corpus = {
  source: {
    project: 'DOMPurify',
    repository: 'https://github.com/cure53/DOMPurify',
    file: 'test/fixtures/expect.mjs',
    version: SOURCE_VERSION,
    commit: SOURCE_COMMIT,
    sha256: SOURCE_SHA256,
    license: 'Apache-2.0',
  },
  modification:
    'neo.sanitize retained fixture payloads and available titles. It added stable labels for untitled fixtures, removed DOMPurify-specific expected output, and checks neo.sanitize security invariants.',
  caseCount: cases.length,
  cases,
}

await writeFile(resolve(outputPath), `${JSON.stringify(corpus, null, 2)}\n`)
console.log(`Wrote ${cases.length} cases to ${outputPath}.`)
