import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { sanitize } from '../../src/index.js'
import corpus from '../corpus/dompurify-v3.4.14.json'
import { assertHTMLSecurityInvariants } from './security-invariants.js'

const CORPUS_FILENAME = 'dompurify-v3.4.14.json'

describe('DOMPurify public fixture corpus', () => {
  it('uses the reviewed version-pinned corpus', () => {
    expect(corpus.source).toMatchObject({
      project: 'DOMPurify',
      repository: 'https://github.com/cure53/DOMPurify',
      file: 'test/fixtures/expect.mjs',
      license: 'Apache-2.0',
    })
    expect(corpus.source.version).toMatch(/^\d+\.\d+\.\d+/u)
    expect(corpus.source.commit).toMatch(/^[0-9a-f]{40}$/u)
    expect(corpus.source.sha256).toMatch(/^[0-9a-f]{64}$/u)
    expect(CORPUS_FILENAME).toBe(`dompurify-v${corpus.source.version}.json`)
    expect(corpus.caseCount).toBe(corpus.cases.length)
    expect(corpus.cases.length).toBeGreaterThanOrEqual(223)

    const notice = readFileSync('test/corpus/THIRD_PARTY_NOTICES.md', 'utf8')
    expect(notice).toContain(corpus.source.commit)
    expect(notice).toContain(corpus.source.sha256)
  })

  it.each(corpus.cases)('$id $title', ({ payload }) => {
    const clean = sanitize(payload) as string
    const sanitizedReparse = sanitize(clean) as string
    const stable = sanitize(payload, { detectMXSS: true }) as string

    assertHTMLSecurityInvariants(clean)
    assertHTMLSecurityInvariants(sanitizedReparse)
    assertHTMLSecurityInvariants(stable)
    expect(sanitize(stable, { detectMXSS: true })).toBe(stable)
  })
})
