// @vitest-environment node

import { JSDOM } from 'jsdom'
import { describe, expect, it } from 'vitest'
import { createSanitizer, sanitize } from '../../../src/core/sanitizer.js'
import { parseHTML, serializeHTML } from '../../../src/core/parser.js'
import type { DOMRuntime } from '../../../src/types.js'

function createRuntime(): DOMRuntime {
  const dom = new JSDOM('')
  return {
    document: dom.window.document,
    DOMParser: dom.window.DOMParser,
  }
}

describe('explicit DOM runtime', () => {
  it('sanitizes in Node.js with a supplied runtime', () => {
    const result = sanitize(
      '<p onclick="alert(1)">Safe</p><script>bad()</script>',
      {},
      createRuntime()
    )

    expect(result).toBe('<p>Safe</p>')
  })

  it('supports reusable sanitizers in Node.js', () => {
    const sanitizer = createSanitizer({ allowedTags: ['p'] }, createRuntime())

    expect(sanitizer.sanitize('<p>Safe</p><img src="x">')).toBe('<p>Safe</p>')
  })

  it('parses and serializes with the supplied runtime', () => {
    const fragment = parseHTML('<p>Safe</p>', createRuntime())

    expect(serializeHTML(fragment)).toBe('<p>Safe</p>')
  })

  it('reuses a parser for repeated calls with the same DOM implementation', () => {
    const runtime = createRuntime()
    const NativeDOMParser = runtime.DOMParser
    let constructorCalls = 0

    class CountingDOMParser {
      private readonly parser: InstanceType<typeof NativeDOMParser>

      constructor() {
        constructorCalls++
        this.parser = new NativeDOMParser()
      }

      parseFromString(html: string, type: 'text/html'): Document {
        return this.parser.parseFromString(html, type)
      }
    }

    const countingRuntime: DOMRuntime = {
      document: runtime.document,
      DOMParser: CountingDOMParser,
    }

    parseHTML('<p>One</p>', countingRuntime)
    parseHTML('<p>Two</p>', countingRuntime)

    expect(constructorCalls).toBe(1)
  })

  it('returns a fragment from the supplied runtime', () => {
    const runtime = createRuntime()
    const result = sanitize('<p>Safe</p>', { returnString: false }, runtime)

    expect(typeof result).toBe('object')
    expect((result as DocumentFragment).ownerDocument).toBe(runtime.document)
  })

  it('reports the missing runtime in Node.js and Web Workers', () => {
    expect(() => sanitize('<p>Safe</p>')).toThrowError(/No DOM runtime is available in Node\.js/)
    expect(() => sanitize('<p>Safe</p>')).toThrowError(/Web Workers must supply/)
  })

  it('fails closed when the DOM runtime parser throws', () => {
    const runtime = createRuntime()
    class ThrowingDOMParser {
      parseFromString(): Document {
        throw new RangeError('runtime parser exhausted its stack')
      }
    }

    expect(
      sanitize('<p>Safe</p>', {}, {
        document: runtime.document,
        DOMParser: ThrowingDOMParser,
      })
    ).toBe('')
  })

  it('normalizes parser errors from the public parser API', () => {
    const runtime = createRuntime()
    class ThrowingDOMParser {
      parseFromString(): Document {
        throw new RangeError('runtime parser exhausted its stack')
      }
    }

    expect(() =>
      parseHTML('<p>Safe</p>', {
        document: runtime.document,
        DOMParser: ThrowingDOMParser,
      })
    ).toThrowError(/DOM runtime failed to parse/)
  })
})
