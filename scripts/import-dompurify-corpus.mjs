import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import {
  createDOMPurifyCorpus,
  getSHA256,
  parseDOMPurifyFixtures,
} from './lib/dompurify-corpus.mjs'

const [sourcePath, version, commit, expectedSHA256, requestedOutputPath] =
  process.argv.slice(2)

if (!sourcePath || !version || !commit || !expectedSHA256) {
  throw new Error(
    'Usage: node scripts/import-dompurify-corpus.mjs <expect.mjs> <version> <commit> <sha256> [output.json]'
  )
}

if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(version)) {
  throw new TypeError('The DOMPurify version is invalid.')
}
if (!/^[0-9a-f]{40}$/u.test(commit)) {
  throw new TypeError('The DOMPurify commit must be a full lowercase SHA-1.')
}
if (!/^[0-9a-f]{64}$/u.test(expectedSHA256)) {
  throw new TypeError('The DOMPurify source checksum must be a lowercase SHA-256.')
}

const source = await readFile(resolve(sourcePath), 'utf8')
const sourceSHA256 = getSHA256(source)
if (sourceSHA256 !== expectedSHA256) {
  throw new Error(
    `The DOMPurify fixture checksum did not match commit ${commit}.`
  )
}

const fixtures = parseDOMPurifyFixtures(source)
const corpus = createDOMPurifyCorpus({
  fixtures,
  version,
  commit,
  sha256: sourceSHA256,
})
const outputPath =
  requestedOutputPath ?? `test/corpus/dompurify-v${version}.json`

await writeFile(resolve(outputPath), `${JSON.stringify(corpus, null, 2)}\n`)
console.log(`Wrote ${fixtures.length} cases to ${outputPath}.`)
