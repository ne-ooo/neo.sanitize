import { Window } from 'happy-dom'
import { describe, expect, it } from 'vitest'
import { sanitize } from '../src/index.js'
import type { DOMRuntime } from '../src/types.js'
import corpus from './corpus/dompurify-v3.4.14.json'
import { assertHTMLSecurityInvariants } from './security/security-invariants.js'

const window = new Window()
const happyDOMRuntime: DOMRuntime = {
  document: window.document as unknown as Document,
  DOMParser: window.DOMParser as unknown as typeof DOMParser,
}

describe('DOM implementation matrix', () => {
  it('does not skip later siblings when nextSibling is incomplete', () => {
    const dirty =
      '<div><form></form><button formaction="javascript:alert(1)">x</button>' +
      '<p>safe</p></div>'

    expect(sanitize(dirty, {}, happyDOMRuntime)).toBe('<div><p>safe</p></div>')
  })

  it('runs the public corpus through happy-dom', () => {
    for (const fixture of corpus.cases) {
      const clean = sanitize(fixture.payload, {}, happyDOMRuntime) as string
      const stable = sanitize(
        fixture.payload,
        { detectMXSS: true },
        happyDOMRuntime
      ) as string

      assertHTMLSecurityInvariants(clean, happyDOMRuntime)
      assertHTMLSecurityInvariants(stable, happyDOMRuntime)
      expect(
        sanitize(stable, { detectMXSS: true }, happyDOMRuntime),
        fixture.id
      ).toBe(stable)
    }
  })
})
