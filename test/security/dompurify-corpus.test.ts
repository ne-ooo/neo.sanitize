import { describe, expect, it } from 'vitest'
import { sanitize } from '../../src/index.js'
import corpus from '../corpus/dompurify-v3.4.14.json'
import { assertHTMLSecurityInvariants } from './security-invariants.js'

describe('DOMPurify public fixture corpus', () => {
  it('uses the reviewed version-pinned corpus', () => {
    expect(corpus.source).toMatchObject({
      project: 'DOMPurify',
      version: '3.4.14',
      commit: '1a49d19d1f57f67e263a3c6213faf7b4e9db8d7a',
      sha256: '1c8f8dad1874fcd375665070a8e2be8e011b63a6d6b2ce27ab08585e324eef75',
      license: 'Apache-2.0',
    })
    expect(corpus.caseCount).toBe(corpus.cases.length)
    expect(corpus.cases).toHaveLength(223)
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
