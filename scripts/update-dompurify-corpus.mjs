import { readFile, readdir, unlink, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import {
  createDOMPurifyCorpus,
  getSHA256,
  parseDOMPurifyFixtures,
} from './lib/dompurify-corpus.mjs'

const repositoryRoot = resolve(import.meta.dirname, '..')
const corpusDirectory = resolve(repositoryRoot, 'test/corpus')
const requestedVersion = process.env.DOMPURIFY_VERSION?.trim()
const githubToken = process.env.GITHUB_TOKEN?.trim()

async function request(url, accept = 'application/vnd.github+json') {
  const headers = {
    Accept: accept,
    'User-Agent': 'neo-sanitize-corpus-updater',
  }
  if (githubToken) headers.Authorization = `Bearer ${githubToken}`

  const response = await fetch(url, { headers })
  if (!response.ok) {
    throw new Error(`Request failed with ${response.status}: ${url}`)
  }
  return response
}

async function getRelease() {
  const endpoint = requestedVersion
    ? `releases/tags/${encodeURIComponent(requestedVersion)}`
    : 'releases/latest'
  const response = await request(
    `https://api.github.com/repos/cure53/DOMPurify/${endpoint}`
  )
  return response.json()
}

async function resolveTagCommit(tagName) {
  const refResponse = await request(
    `https://api.github.com/repos/cure53/DOMPurify/git/ref/tags/${encodeURIComponent(tagName)}`
  )
  let object = (await refResponse.json()).object

  for (let depth = 0; object?.type === 'tag' && depth < 5; depth++) {
    const tagResponse = await request(object.url)
    object = (await tagResponse.json()).object
  }

  if (object?.type !== 'commit' || !/^[0-9a-f]{40}$/u.test(object.sha)) {
    throw new TypeError('The DOMPurify release tag did not resolve to a commit.')
  }
  return object.sha
}

function createNotice({ filename, version, commit, sha256 }) {
  return `# Third-Party Test Corpus

\`${filename}\` contains modified test fixtures from DOMPurify.

- Project: DOMPurify
- Source: \`test/fixtures/expect.mjs\`
- Version: ${version}
- Commit: \`${commit}\`
- Source SHA-256: \`${sha256}\`
- Copyright: Cure53 and other contributors
- License: Apache License 2.0
- Repository: <https://github.com/cure53/DOMPurify>

neo.sanitize retained each payload and each available title. It added stable labels for untitled fixtures.

neo.sanitize removed the DOMPurify-specific expected output.

neo.sanitize checks its own HTML-only security invariants. DOMPurify and Cure53 do not endorse these modifications.

The full Apache License 2.0 is in \`LICENSE-DOMPURIFY.txt\`.
`
}

async function writeIfChanged(path, content) {
  let current = ''
  try {
    current = await readFile(path, 'utf8')
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
  }
  if (current === content) return false
  await writeFile(path, content)
  return true
}

const release = await getRelease()
const tagName = release.tag_name
if (typeof tagName !== 'string') {
  throw new TypeError('The latest DOMPurify release has no tag name.')
}
const version = tagName.replace(/^v/u, '')
if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(version)) {
  throw new TypeError(`The DOMPurify release version is invalid: ${tagName}`)
}

const commit = await resolveTagCommit(tagName)
const rawBase = `https://raw.githubusercontent.com/cure53/DOMPurify/${commit}`
const fixtureResponse = await request(
  `${rawBase}/test/fixtures/expect.mjs`,
  'text/plain'
)
const fixtureSource = await fixtureResponse.text()
const sourceSHA256 = getSHA256(fixtureSource)
const fixtures = parseDOMPurifyFixtures(fixtureSource)
const corpus = createDOMPurifyCorpus({
  fixtures,
  version,
  commit,
  sha256: sourceSHA256,
})

const corpusFiles = (await readdir(corpusDirectory)).filter((file) =>
  /^dompurify-v.+\.json$/u.test(file)
)
if (corpusFiles.length !== 1) {
  throw new Error('Expected exactly one versioned DOMPurify corpus file.')
}

const oldFilename = corpusFiles[0]
const newFilename = `dompurify-v${version}.json`
const referenceUpdates = []

if (oldFilename !== newFilename) {
  const referenceFiles = [
    'test/runtime-matrix.test.ts',
    'test/security/dompurify-corpus.test.ts',
    'test/differential/arbitraries.ts',
    'test/fuzz/sanitize.fast-check.test.ts',
    'test/browser/security.spec.ts',
  ]
  for (const relativePath of referenceFiles) {
    const path = resolve(repositoryRoot, relativePath)
    const source = await readFile(path, 'utf8')
    if (!source.includes(oldFilename)) {
      throw new Error(`${relativePath} does not reference ${oldFilename}.`)
    }
    referenceUpdates.push([
      path,
      source.replaceAll(oldFilename, newFilename),
    ])
  }
}

const licenseResponse = await request(`${rawBase}/LICENSE`, 'text/plain')
const license = await licenseResponse.text()

let changed = await writeIfChanged(
  resolve(corpusDirectory, newFilename),
  `${JSON.stringify(corpus, null, 2)}\n`
)

if (oldFilename !== newFilename) {
  for (const [path, source] of referenceUpdates) {
    await writeFile(path, source)
  }
  await unlink(resolve(corpusDirectory, oldFilename))
  changed = true
}

changed =
  (await writeIfChanged(
    resolve(corpusDirectory, 'THIRD_PARTY_NOTICES.md'),
    createNotice({
      filename: newFilename,
      version,
      commit,
      sha256: sourceSHA256,
    })
  )) || changed

changed =
  (await writeIfChanged(
    resolve(corpusDirectory, 'LICENSE-DOMPURIFY.txt'),
    license.endsWith('\n') ? license : `${license}\n`
  )) || changed

const outputs = {
  changed: String(changed),
  version,
  commit,
  case_count: String(fixtures.length),
  corpus_file: newFilename,
}
if (process.env.GITHUB_OUTPUT) {
  const lines = Object.entries(outputs)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n')
  await writeFile(process.env.GITHUB_OUTPUT, `${lines}\n`, { flag: 'a' })
}

console.log(JSON.stringify(outputs))
