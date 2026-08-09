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

function assertBundleBudget() {
  const esmEntry = readFileSync(resolvePackagePath(manifest.module))
  const compressedBytes = gzipSync(esmEntry, { level: 9 }).byteLength
  const maximumBytes = 15 * 1024

  assert.ok(
    compressedBytes <= maximumBytes,
    `The gzipped ESM entry is ${compressedBytes} bytes. The limit is ${maximumBytes} bytes.`
  )
  return compressedBytes
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
}

assert.equal(Object.keys(manifest.dependencies ?? {}).length, 0, 'Runtime dependencies are not allowed')
assertPublishedFilesExist()
assertSkillVersionsMatch()

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

const compressedBytes = assertBundleBudget()
console.log(`Package verification passed. Gzipped ESM entry: ${compressedBytes} bytes.`)
