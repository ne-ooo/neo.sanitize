import { describe, expect, it } from 'vitest'
import { compileSanitizeOptions, sanitize } from '../../../src/core/sanitizer.js'
import type { DOMRuntime } from '../../../src/types.js'

describe('wrapper removal', () => {
  it('unwraps unknown elements after sanitizing their descendants', () => {
    const result = sanitize(
      '<section><p onclick="alert(1)"><strong>Safe</strong><script>bad()</script></p></section>'
    )

    expect(result).toBe('<p><strong>Safe</strong></p>')
  })

  it('removes an unknown subtree when text retention is disabled', () => {
    const result = sanitize('<section><p>Remove</p></section><p>Keep</p>', {
      keepTextContent: false,
    })

    expect(result).toBe('<p>Keep</p>')
  })

  it('strips allowed wrappers and keeps sanitized descendants', () => {
    const result = sanitize(
      '<p><strong>Bold</strong><a href="javascript:alert(1)"> link</a><script>bad()</script></p>',
      { stripTags: true }
    )

    expect(result).toBe('Bold link')
  })

  it('always removes dangerous subtrees when stripTags is enabled', () => {
    const result = sanitize('<style>body { color: red }</style><script>alert(1)</script>Safe', {
      stripTags: true,
    })

    expect(result).toBe('Safe')
  })

  it('builds output without reinserting nested denied wrappers', () => {
    const depth = 400
    const html = `${'<x>t'.repeat(depth)}${'</x>'.repeat(depth)}`
    const originalInsertBefore = Node.prototype.insertBefore
    let insertionCount = 0

    Node.prototype.insertBefore = function <T extends Node>(
      newNode: T,
      referenceNode: Node | null
    ): T {
      insertionCount++
      return originalInsertBefore.call(this, newNode, referenceNode) as T
    }

    try {
      expect(sanitize(html)).toBe('t'.repeat(depth))
    } finally {
      Node.prototype.insertBefore = originalInsertBefore
    }

    expect(insertionCount).toBe(1)
  })

  it('rebuilds only the denied subtree', () => {
    const cleanNodes = '<span>safe</span>'.repeat(100)
    const html = `${cleanNodes}<section><strong>kept</strong></section>${cleanNodes}`
    const originalCloneNode = Node.prototype.cloneNode
    let cloneCount = 0

    Node.prototype.cloneNode = function (deep?: boolean): Node {
      cloneCount++
      return originalCloneNode.call(this, deep)
    }

    try {
      expect(sanitize(html)).toBe(
        `${cleanNodes}<strong>kept</strong>${cleanNodes}`
      )
    } finally {
      Node.prototype.cloneNode = originalCloneNode
    }

    expect(cloneCount).toBe(2)
  })
})

describe('compiled options', () => {
  it('creates a frozen reusable policy for direct sanitize calls', () => {
    const options = compileSanitizeOptions({
      allowedTags: ['p'],
      allowedAttributes: {},
    })

    expect(Object.isFrozen(options)).toBe(true)
    expect(Object.isFrozen(options.allowedTags)).toBe(true)
    expect(sanitize('<p>Keep</p><img src="x">', options)).toBe('<p>Keep</p>')
    expect(sanitize('<p>Again</p>', options)).toBe('<p>Again</p>')
  })

  it('rejects hooks instead of silently discarding them', () => {
    expect(() =>
      compileSanitizeOptions({
        hooks: { onElement: () => false },
      } as never)
    ).toThrow('compileSanitizeOptions() rejects hooks')
  })

  it('rejects inherited hooks instead of silently discarding them', () => {
    const options = Object.create({
      hooks: { onElement: () => false },
    })

    expect(() => compileSanitizeOptions(options)).toThrow(
      'compileSanitizeOptions() rejects hooks'
    )
  })
})

describe('mXSS stabilization', () => {
  it('reuses the stable serialization for string output', () => {
    const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')
    if (!descriptor?.get) throw new Error('The DOM runtime must expose innerHTML.')

    let reads = 0
    Object.defineProperty(Element.prototype, 'innerHTML', {
      ...descriptor,
      get() {
        reads++
        return descriptor.get?.call(this)
      },
    })

    try {
      expect(sanitize('<p>safe</p>', { detectMXSS: true })).toBe('<p>safe</p>')
    } finally {
      Object.defineProperty(Element.prototype, 'innerHTML', descriptor)
    }

    expect(reads).toBe(2)
  })
})

describe('resource limits', () => {
  it('rejects oversized input before DOM parsing', () => {
    expect(sanitize('<p>Safe</p>', { maxInputLength: 8 })).toBe('')
  })

  it('rejects oversized input before invoking beforeSanitize', () => {
    let hookCalls = 0
    expect(
      sanitize('<p>Safe</p>', {
        maxInputLength: 8,
        hooks: {
          beforeSanitize() {
            hookCalls++
          },
        },
      })
    ).toBe('')
    expect(hookCalls).toBe(0)
  })

  it('checks the input limit after beforeSanitize', () => {
    expect(
      sanitize('x', {
        maxInputLength: 8,
        hooks: { beforeSanitize: () => '<p>Expanded</p>' },
      })
    ).toBe('')
  })

  it('fails closed when the DOM node budget is exhausted', () => {
    expect(sanitize('<p>One</p><p>Two</p>', { maxDOMNodes: 2 })).toBe('')
  })

  it('supports a custom DOM depth limit', () => {
    expect(sanitize('<div><div>Safe</div></div>', { maxDOMDepth: 1 })).toBe('')
  })

  it('preflights excessive raw nesting before constructing a DOM parser', () => {
    let parserConstructions = 0
    class CountingDOMParser {
      constructor() {
        parserConstructions++
      }

      parseFromString(): Document {
        return document.implementation.createHTMLDocument('')
      }
    }

    expect(
      sanitize('<div><div>Safe</div></div>', { maxDOMDepth: 1 }, {
        document,
        DOMParser: CountingDOMParser,
      })
    ).toBe('')
    expect(parserConstructions).toBe(0)
  })

  it('treats self-closing syntax on non-void HTML elements as opening tags', () => {
    const inputs = [
      '<div/><div/>',
      '<x-custom/><x-custom/>',
      '<div / ><div / >',
    ]

    for (const html of inputs) {
      let parserConstructions = 0
      class CountingDOMParser {
        constructor() {
          parserConstructions++
        }

        parseFromString(): Document {
          return document.implementation.createHTMLDocument('')
        }
      }

      expect(
        sanitize(html, { maxDOMDepth: 1 }, {
          document,
          DOMParser: CountingDOMParser,
        })
      ).toBe('')
      expect(parserConstructions).toBe(0)
    }
  })

  it('counts complete HTML tag names during the nesting preflight', () => {
    const inputs = [
      '<x.y></x><x.y></x>',
      '<x_y></x><x_y></x>',
      '<xé></x><xé></x>',
    ]

    for (const html of inputs) {
      let parserConstructions = 0
      class CountingDOMParser {
        constructor() {
          parserConstructions++
        }

        parseFromString(): Document {
          return document.implementation.createHTMLDocument('')
        }
      }

      expect(
        sanitize(html, { maxDOMDepth: 1 }, {
          document,
          DOMParser: CountingDOMParser,
        })
      ).toBe('')
      expect(parserConstructions).toBe(0)
    }
  })

  it('matches HTML tokenization at depth-preflight boundaries', () => {
    const cases = [
      { html: '<div></ div><div></ div>', maxDOMDepth: 1 },
      { html: '<x\u00a0y></x><x\u00a0y></x>', maxDOMDepth: 1 },
      { html: '<x\u000by></x><x\u000by></x>', maxDOMDepth: 1 },
      { html: '<xK></xk><xK></xk>', maxDOMDepth: 1 },
      { html: '<!-- --!><div><!-- --!><div>', maxDOMDepth: 1 },
      {
        html: '<div><script></div></script><div><script></div></script>',
        maxDOMDepth: 2,
      },
      {
        html:
          '<div><script><!--<script></script></div></script>' +
          '<div><script><!--<script></script></div></script>',
        maxDOMDepth: 2,
      },
      { html: '<svg><title><g><g></title></svg>', maxDOMDepth: 2 },
      { html: `<svg>${'<option>'.repeat(5)}`, maxDOMDepth: 2 },
      { html: `<svg><plaintext>${'<g>'.repeat(5)}`, maxDOMDepth: 2 },
      {
        html: '<div><svg><![CDATA[></svg></div>]]></svg>'.repeat(3),
        maxDOMDepth: 2,
      },
      { html: '<svg><p><![CDATA[><span><span>]]>', maxDOMDepth: 2 },
      {
        html: '<svg><foreignObject><![CDATA[><span><span>]]></foreignObject></svg>',
        maxDOMDepth: 2,
      },
      { html: '<svg><desc><![CDATA[><span><span>]]></desc></svg>', maxDOMDepth: 2 },
      { html: '<math><mi><![CDATA[><span><span>]]></mi></math>', maxDOMDepth: 2 },
      {
        html:
          '<math><annotation-xml encoding="text/html"><![CDATA[>' +
          '<span><span>]]></annotation-xml></math>',
        maxDOMDepth: 2,
      },
      {
        html: '<div><x a="x"b="></x></div>">'.repeat(3),
        maxDOMDepth: 2,
      },
      {
        html: '<select><xmp></select><div><div><div></xmp>',
        maxDOMDepth: 2,
      },
      {
        html:
          '<svg><foreignObject><script><!--</script></foreignObject></svg>' +
          '<div><div><div><div>',
        maxDOMDepth: 3,
      },
      { html: '<table><td>'.repeat(512), maxDOMDepth: 1_024 },
    ]

    for (const { html, maxDOMDepth } of cases) {
      let parserConstructions = 0
      class CountingDOMParser {
        constructor() {
          parserConstructions++
        }

        parseFromString(): Document {
          return document.implementation.createHTMLDocument('')
        }
      }

      expect(
        sanitize(html, { maxDOMDepth }, {
          document,
          DOMParser: CountingDOMParser,
        })
      ).toBe('')
      expect(parserConstructions).toBe(0)
    }
  })

  it('ignores markup-like text inside comments and raw-text elements', () => {
    expect(sanitize('<!-- <div><div> --><p>safe</p>', { maxDOMDepth: 1 })).toBe(
      '<p>safe</p>'
    )
    expect(
      sanitize('<script><div><div></script><p>safe</p>', { maxDOMDepth: 1 })
    ).toBe('<p>safe</p>')
  })

  it('accounts for optional HTML end tags during nesting preflight', () => {
    expect(sanitize('<p>One<p>Two<p>Three', { maxDOMDepth: 1 })).toBe(
      '<p>One</p><p>Two</p><p>Three</p>'
    )
  })

  it('fails closed before a deep DOM can exhaust the call stack', () => {
    const depth = 1_100
    const html = `${'<div>'.repeat(depth)}safe${'</div>'.repeat(depth)}`

    expect(sanitize(html)).toBe('')
  })

  it('fails closed for deep hook and mXSS paths', () => {
    const depth = 1_100
    const html = `${'<div>'.repeat(depth)}safe${'</div>'.repeat(depth)}`

    expect(
      sanitize(html, {
        detectMXSS: true,
        hooks: { onElement: () => undefined },
      })
    ).toBe('')
  })

  it('supports the configured depth boundary with a non-recursive runtime serializer', () => {
    const depth = 1_024
    const html = `${'<div>'.repeat(depth)}safe${'</div>'.repeat(depth)}`
    const result = sanitize(html, { returnString: false })
    expect((result as DocumentFragment).textContent).toBe('safe')
  })
})
