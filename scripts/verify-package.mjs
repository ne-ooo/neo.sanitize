import assert from 'node:assert/strict'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'
import { createRequire } from 'node:module'
import { JSDOM } from 'jsdom'

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const packageJsonPath = resolve(packageRoot, 'package.json')
const manifest = JSON.parse(readFileSync(packageJsonPath, 'utf8'))
const require = createRequire(import.meta.url)

function resolvePackagePath(path) {
  return resolve(packageRoot, path.replace(/^\.\//, ''))
}

function assertPublishedFilesExist() {
  const requiredFiles = ['README.md', 'CHANGELOG.md', 'LICENSE', 'SECURITY.md']
  for (const file of requiredFiles) {
    assert.ok(manifest.files.includes(file), `${file} is missing from package.json files`)
    assert.ok(existsSync(resolve(packageRoot, file)), `${file} does not exist`)
  }

  for (const [subpath, target] of Object.entries(manifest.exports)) {
    if (typeof target === 'string') {
      assert.ok(existsSync(resolvePackagePath(target)), `${subpath} export does not exist`)
      continue
    }

    for (const [format, path] of Object.entries(target)) {
      assert.ok(existsSync(resolvePackagePath(path)), `${subpath} ${format} export does not exist`)
    }
  }
}

function assertSkillVersionsMatch() {
  const skillsDirectory = resolve(packageRoot, '.lpm/skills')
  const skillFiles = readdirSync(skillsDirectory).filter((file) => file.endsWith('.md'))

  assert.ok(skillFiles.length > 0, 'The package must include at least one skill file')
  for (const file of skillFiles) {
    const contents = readFileSync(resolve(skillsDirectory, file), 'utf8')
    const version = contents.match(/^version:\s*"([^"]+)"/m)?.[1]
    assert.equal(version, manifest.version, `${file} version does not match package.json`)
  }
}

function assertPublishedLPMFilesAreScoped() {
  assert.ok(
    manifest.files.includes('.lpm/skills'),
    'package.json files must include .lpm/skills'
  )
  assert.ok(
    !manifest.files.includes('.lpm'),
    'package.json files must not publish generated .lpm state'
  )
}

function assertBundleBudget() {
  const esmEntry = readFileSync(resolvePackagePath(manifest.module))
  const compressedBytes = gzipSync(esmEntry, { level: 9 }).byteLength
  const maximumCompressedBytes = 15 * 1024
  const maximumRawBytes = 41 * 1024
  const distributionBytes = getDirectorySize(resolve(packageRoot, 'dist'))
  const maximumDistributionBytes = 350 * 1024

  assert.ok(
    compressedBytes <= maximumCompressedBytes,
    `The gzipped ESM entry is ${compressedBytes} bytes. The limit is ${maximumCompressedBytes} bytes.`
  )
  assert.ok(
    esmEntry.byteLength <= maximumRawBytes,
    `The raw ESM entry is ${esmEntry.byteLength} bytes. The limit is ${maximumRawBytes} bytes.`
  )
  assert.ok(
    distributionBytes <= maximumDistributionBytes,
    `The dist directory is ${distributionBytes} bytes. The limit is ${maximumDistributionBytes} bytes.`
  )

  return {
    compressedBytes,
    rawBytes: esmEntry.byteLength,
    distributionBytes,
  }
}

function getDirectorySize(directory) {
  let bytes = 0

  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const entryPath = resolve(directory, entry.name)
    bytes += entry.isDirectory()
      ? getDirectorySize(entryPath)
      : readFileSync(entryPath).byteLength
  }

  return bytes
}

function createRuntime() {
  const dom = new JSDOM('')
  return {
    document: dom.window.document,
    DOMParser: dom.window.DOMParser,
  }
}

function assertSanitizer(module, runtime) {
  const input = '<script>alert(1)</script><p onclick="alert(1)">Safe</p>'
  assert.equal(module.sanitize(input, {}, runtime), '<p>Safe</p>')
  assert.equal(typeof module.sanitizeToTrustedHTML, 'function')
}

assert.equal(Object.keys(manifest.dependencies ?? {}).length, 0, 'Runtime dependencies are not allowed')
assertPublishedFilesExist()
assertSkillVersionsMatch()
assertPublishedLPMFilesAreScoped()

const [esmRoot, esmCore, esmValidators, esmSchemas] = await Promise.all([
  import(manifest.name),
  import(`${manifest.name}/core`),
  import(`${manifest.name}/validators`),
  import(`${manifest.name}/schemas`),
])
const cjsRoot = require(manifest.name)
const cjsCore = require(`${manifest.name}/core`)
const cjsValidators = require(`${manifest.name}/validators`)
const cjsSchemas = require(`${manifest.name}/schemas`)
const runtime = createRuntime()

assertSanitizer(esmRoot, runtime)
assertSanitizer(esmCore, runtime)
assertSanitizer(cjsRoot, runtime)
assertSanitizer(cjsCore, runtime)
assert.equal(esmValidators.isDangerousProtocol('javascript'), true)
assert.equal(cjsValidators.isDangerousProtocol('javascript'), true)
assert.deepEqual(esmSchemas.STRICT_SCHEMA.allowedTags, [])
assert.deepEqual(cjsSchemas.STRICT_SCHEMA.allowedTags, [])

const bundle = assertBundleBudget()
console.log(
  'Package verification passed. ' +
    `ESM entry: ${bundle.rawBytes} bytes raw, ${bundle.compressedBytes} bytes gzip. ` +
    `Dist: ${bundle.distributionBytes} bytes.`
)
