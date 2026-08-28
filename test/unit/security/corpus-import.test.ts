// @vitest-environment node

import { describe, expect, it } from 'vitest'
import {
  createDOMPurifyCorpus,
  getSHA256,
  parseDOMPurifyFixtures,
} from '../../../scripts/lib/dompurify-corpus.mjs'

describe('DOMPurify corpus import', () => {
  it('parses one static JSON-compatible export', () => {
    const fixtures = parseDOMPurifyFixtures(`export default [
      { "title": "case", "payload": "<img onerror=alert(1)>" },
    ];`)

    expect(fixtures).toEqual([
      { title: 'case', payload: '<img onerror=alert(1)>' },
    ])
  })

  it('rejects executable fixture modules', () => {
    expect(() =>
      parseDOMPurifyFixtures(
        'export default []; globalThis.compromised = true;'
      )
    ).toThrow(/static JSON-compatible array/)
  })

  it('creates attributed corpus metadata without expected output', () => {
    const source = 'export default [{ "payload": "<p>safe</p>" }];\n'
    const corpus = createDOMPurifyCorpus({
      fixtures: parseDOMPurifyFixtures(source),
      version: '3.4.14',
      commit: 'a'.repeat(40),
      sha256: getSHA256(source),
    })

    expect(corpus.caseCount).toBe(1)
    expect(corpus.source.sha256).toBe(getSHA256(source))
    expect(corpus.cases[0]).toEqual({
      id: 'dompurify-001',
      title: 'Untitled fixture 1',
      payload: '<p>safe</p>',
    })
    expect(corpus.cases[0]).not.toHaveProperty('expected')
  })
})
