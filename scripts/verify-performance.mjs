import assert from 'node:assert/strict'
import { performance } from 'node:perf_hooks'
import { Window } from 'happy-dom'
import { JSDOM } from 'jsdom'
import { isSafeURLAttributeValue, sanitize } from '../dist/index.js'

const MEBIBYTE = 1024 * 1024
const window = new JSDOM('').window
const runtime = {
  document: window.document,
  DOMParser: window.DOMParser,
}

function medianDuration(operation, samples = 5) {
  const durations = []
  for (let index = 0; index < samples; index++) {
    const start = performance.now()
    operation()
    durations.push(performance.now() - start)
  }

  durations.sort((left, right) => left - right)
  return durations[Math.floor(durations.length / 2)]
}

function heapGrowth(operation) {
  globalThis.gc()
  const before = process.memoryUsage().heapUsed
  operation()
  return Math.max(0, process.memoryUsage().heapUsed - before)
}

function ratio(larger, smaller) {
  return larger / Math.max(smaller, 0.001)
}

if (typeof globalThis.gc !== 'function') {
  throw new Error('Run the performance checks with the --expose-gc option.')
}

const sample = '<p>Safe <strong>text</strong></p><script>bad()</script>'
const expectedSample = '<p>Safe <strong>text</strong></p>'
const explicitResult = sanitize(sample, {}, runtime)
assert.equal(explicitResult, expectedSample)

const previousDocument = globalThis.document
const previousDOMParser = globalThis.DOMParser
globalThis.document = window.document
globalThis.DOMParser = window.DOMParser
try {
  assert.equal(sanitize(sample), explicitResult)
} finally {
  if (previousDocument === undefined) delete globalThis.document
  else globalThis.document = previousDocument
  if (previousDOMParser === undefined) delete globalThis.DOMParser
  else globalThis.DOMParser = previousDOMParser
}

const cleanSmall = '<span>safe</span>'.repeat(5_000)
const cleanLarge = cleanSmall.repeat(2)
const wrapper = '<section><strong>kept</strong></section>'
const expectedWrapped = `${cleanLarge}<strong>kept</strong>`

assert.equal(sanitize(cleanLarge + wrapper, {}, runtime), expectedWrapped)
sanitize(cleanSmall, {}, runtime)
sanitize(cleanLarge, {}, runtime)
sanitize(cleanLarge + wrapper, {}, runtime)

const cleanSmallMs = medianDuration(() => sanitize(cleanSmall, {}, runtime))
const cleanLargeMs = medianDuration(() => sanitize(cleanLarge, {}, runtime))
const wrappedMs = medianDuration(() => sanitize(cleanLarge + wrapper, {}, runtime))
const cleanHeap = heapGrowth(() => sanitize(cleanLarge, {}, runtime))
const wrappedHeap = heapGrowth(() => sanitize(cleanLarge + wrapper, {}, runtime))

assert.ok(
  ratio(cleanLargeMs, cleanSmallMs) < 3.5,
  'Wide-document runtime scaled beyond the regression limit.'
)
assert.ok(
  ratio(wrappedMs, cleanLargeMs) < 1.75,
  'One denied wrapper rebuilt too much of the document.'
)
assert.ok(
  ratio(wrappedHeap, cleanHeap) < 1.75,
  'One denied wrapper used too much additional heap.'
)

const cssTerms = '1px + '.repeat(2_000) + '1px'
const flatCSS = `<div style="width: calc(${cssTerms})">x</div>`
const nestedCSS = `<div style="width: ${'calc('.repeat(32)}${cssTerms}${')'.repeat(32)}">x</div>`
const cssOptions = {
  allowedTags: ['div'],
  allowedAttributes: { div: ['style'] },
  allowStyleAttribute: true,
  strictCSSValidation: true,
}

sanitize(flatCSS, cssOptions, runtime)
sanitize(nestedCSS, cssOptions, runtime)
const flatCSSMs = medianDuration(() => sanitize(flatCSS, cssOptions, runtime))
const nestedCSSMs = medianDuration(() => sanitize(nestedCSS, cssOptions, runtime))
assert.ok(
  ratio(nestedCSSMs, flatCSSMs) < 3,
  'Nested CSS functions amplified tokenizer work beyond the regression limit.'
)

class EmptyDOMParser {
  parseFromString() {
    return window.document.implementation.createHTMLDocument('')
  }
}
const preflightRuntime = {
  document: window.document,
  DOMParser: EmptyDOMParser,
}
const rawTextPairs = '<xmp></xmp>'.repeat(15_000)
const flatPreflightInput = rawTextPairs + '<x>'.repeat(1_025)
const deepPreflightInput =
  '<x>'.repeat(1_000) + rawTextPairs + '<x>'.repeat(25)
const preflightOptions = { maxDOMDepth: 1_024 }

sanitize(flatPreflightInput, preflightOptions, preflightRuntime)
sanitize(deepPreflightInput, preflightOptions, preflightRuntime)
const flatPreflightMs = medianDuration(() =>
  sanitize(flatPreflightInput, preflightOptions, preflightRuntime)
)
const deepPreflightMs = medianDuration(() =>
  sanitize(deepPreflightInput, preflightOptions, preflightRuntime)
)
assert.ok(
  ratio(deepPreflightMs, flatPreflightMs) < 3,
  'Raw-text preflight work scaled with lexical depth.'
)

const safeCandidates = Array.from(
  { length: 500_000 },
  (_, index) => `https://img.test/${index}.png 1x`
).join(',')
const unsafeFirst = `javascript:alert(1),${safeCandidates}`
const urlStart = performance.now()
const urlHeap = heapGrowth(() => {
  assert.equal(isSafeURLAttributeValue('srcset', unsafeFirst), false)
})
const urlMs = performance.now() - urlStart

assert.ok(urlMs < 250, 'Unsafe-first URL-list validation did not stop early.')
assert.ok(urlHeap < 24 * MEBIBYTE, 'Unsafe-first URL-list validation allocated too much heap.')

const happyWindow = new Window()
const happyRuntime = {
  document: happyWindow.document,
  DOMParser: happyWindow.DOMParser,
}
const contextualSmall = '<p>x</p>'.repeat(8_000)
const contextualLarge = contextualSmall.repeat(2)
const contextualOptions = { insertionContext: 'div' }

sanitize(contextualSmall, contextualOptions, happyRuntime)
sanitize(contextualLarge, contextualOptions, happyRuntime)
const contextualSmallMs = medianDuration(
  () => sanitize(contextualSmall, contextualOptions, happyRuntime),
  3
)
const contextualLargeMs = medianDuration(
  () => sanitize(contextualLarge, contextualOptions, happyRuntime),
  3
)
assert.ok(
  ratio(contextualLargeMs, contextualSmallMs) < 2.8,
  'Contextual top-level traversal scaled beyond the regression limit.'
)

console.log(
  JSON.stringify({
    cleanScalingRatio: ratio(cleanLargeMs, cleanSmallMs),
    deniedWrapperTimeRatio: ratio(wrappedMs, cleanLargeMs),
    deniedWrapperHeapRatio: ratio(wrappedHeap, cleanHeap),
    contextualSmallMilliseconds: contextualSmallMs,
    contextualLargeMilliseconds: contextualLargeMs,
    contextualScalingRatio: ratio(contextualLargeMs, contextualSmallMs),
    nestedCSSRatio: ratio(nestedCSSMs, flatCSSMs),
    rawTextPreflightRatio: ratio(deepPreflightMs, flatPreflightMs),
    unsafeFirstURLMilliseconds: urlMs,
    unsafeFirstURLHeapBytes: urlHeap,
  })
)
