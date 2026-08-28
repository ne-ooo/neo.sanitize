import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'

const outputPath = process.argv[2]
const suite = process.argv[3] ?? 'security'
if (!outputPath) {
  throw new Error(
    'Usage: node scripts/write-security-metadata.mjs <output.json> [suite]'
  )
}

const packageManifest = JSON.parse(await readFile('package.json', 'utf8'))
const corpusFilename = (await readdir('test/corpus')).find((filename) =>
  /^dompurify-v.+\.json$/u.test(filename)
)
if (!corpusFilename) {
  throw new Error('The DOMPurify corpus file is missing.')
}
const corpus = JSON.parse(
  await readFile(resolve('test/corpus', corpusFilename), 'utf8')
)

const metadata = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  suite,
  sanitizer: {
    name: packageManifest.name,
    version: packageManifest.version,
  },
  source: {
    repository: process.env.GITHUB_REPOSITORY ?? null,
    commit: process.env.GITHUB_SHA ?? null,
    ref: process.env.GITHUB_REF ?? null,
    runId: process.env.GITHUB_RUN_ID ?? null,
    runAttempt: process.env.GITHUB_RUN_ATTEMPT ?? null,
  },
  runtime: {
    node: process.version,
    platform: process.platform,
    architecture: process.arch,
  },
  corpus: {
    filename: corpusFilename,
    ...corpus.source,
    caseCount: corpus.caseCount,
  },
  fuzz: {
    runs: process.env.FUZZ_RUNS ?? null,
    differentialRuns: process.env.DIFFERENTIAL_FUZZ_RUNS ?? null,
    adversarialContextRuns:
      process.env.ADVERSARIAL_CONTEXT_FUZZ_RUNS ?? null,
    browserRuns: process.env.BROWSER_FUZZ_RUNS ?? null,
    browserDifferentialRuns:
      process.env.BROWSER_DIFFERENTIAL_RUNS ?? null,
  },
}

const absoluteOutput = resolve(outputPath)
await mkdir(dirname(absoluteOutput), { recursive: true })
await writeFile(absoluteOutput, `${JSON.stringify(metadata, null, 2)}\n`)
console.log(`Wrote ${absoluteOutput}.`)
