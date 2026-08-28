// @vitest-environment node

import { JSDOM } from 'jsdom'
import { describe, expect, it } from 'vitest'
import { sanitize } from '../../../src/core/sanitizer.js'
import { parseHTML, serializeHTML } from '../../../src/core/parser.js'
import type { DOMRuntime } from '../../../src/types.js'

function createRuntime(): { dom: JSDOM; runtime: DOMRuntime } {
  const dom = new JSDOM('')
  return {
    dom,
    runtime: {
      document: dom.window.document,
      DOMParser: dom.window.DOMParser,
    },
  }
}

describe('captured DOM intrinsics', () => {
  it('keeps using validated operations after runtime prototypes change', () => {
    const { dom, runtime } = createRuntime()
    const options = { hooks: { onElement: () => undefined } }

    expect(sanitize('<p onclick=alert(1)>safe</p>', options, runtime)).toBe(
      '<p>safe</p>'
    )

    const nodePrototype = dom.window.Node.prototype
    const elementPrototype = dom.window.Element.prototype
    const originalAppendChild = nodePrototype.appendChild
    const originalCloneNode = nodePrototype.cloneNode
    const originalHasAttribute = elementPrototype.hasAttribute
    const originalInnerHTML = Object.getOwnPropertyDescriptor(
      elementPrototype,
      'innerHTML'
    )
    if (!originalInnerHTML) throw new Error('innerHTML is unavailable')

    nodePrototype.appendChild = () => {
      throw new Error('patched appendChild ran')
    }
    nodePrototype.cloneNode = () => {
      throw new Error('patched cloneNode ran')
    }
    elementPrototype.hasAttribute = () => {
      throw new Error('patched hasAttribute ran')
    }
    Object.defineProperty(elementPrototype, 'innerHTML', {
      ...originalInnerHTML,
      get() {
        throw new Error('patched innerHTML getter ran')
      },
      set() {
        throw new Error('patched innerHTML setter ran')
      },
    })

    try {
      expect(sanitize('<p onclick=alert(1)>safe</p>', options, runtime)).toBe(
        '<p>safe</p>'
      )
    } finally {
      nodePrototype.appendChild = originalAppendChild
      nodePrototype.cloneNode = originalCloneNode
      elementPrototype.hasAttribute = originalHasAttribute
      Object.defineProperty(elementPrototype, 'innerHTML', originalInnerHTML)
    }
  })

  it('keeps using captured attribute operations after runtime prototypes change', () => {
    const { dom, runtime } = createRuntime()
    const input = '<img src=x onerror=alert(1)>'

    expect(sanitize(input, {}, runtime)).toBe('<img src="x">')

    const mapPrototype = dom.window.NamedNodeMap.prototype
    const attributePrototype = dom.window.Attr.prototype
    const originalItem = mapPrototype.item
    const originalLength = Object.getOwnPropertyDescriptor(
      mapPrototype,
      'length'
    )
    const originalName = Object.getOwnPropertyDescriptor(
      attributePrototype,
      'name'
    )
    const originalValue = Object.getOwnPropertyDescriptor(
      attributePrototype,
      'value'
    )
    if (!originalLength || !originalName || !originalValue) {
      throw new Error('Attribute accessors are unavailable')
    }

    mapPrototype.item = () => null
    Object.defineProperty(mapPrototype, 'length', {
      ...originalLength,
      get: () => 0,
    })
    Object.defineProperty(attributePrototype, 'name', {
      ...originalName,
      get: () => 'src',
    })
    Object.defineProperty(attributePrototype, 'value', {
      ...originalValue,
      get: () => 'https://example.com',
    })

    try {
      expect(sanitize(input, {}, runtime)).toBe('<img src="x">')
      expect(
        sanitize(
          input,
          { hooks: { onAttribute: () => undefined } },
          runtime
        )
      ).toBe('<img src="x">')
    } finally {
      mapPrototype.item = originalItem
      Object.defineProperty(mapPrototype, 'length', originalLength)
      Object.defineProperty(attributePrototype, 'name', originalName)
      Object.defineProperty(attributePrototype, 'value', originalValue)
    }
  })

  it('keeps using the captured parser after its prototype changes', () => {
    const { dom, runtime } = createRuntime()
    expect(sanitize('<p>warm</p>', {}, runtime)).toBe('<p>warm</p>')

    const parserPrototype = dom.window.DOMParser.prototype
    const originalParseFromString = parserPrototype.parseFromString
    let divertedCalls = 0
    parserPrototype.parseFromString = () => {
      divertedCalls++
      return runtime.document
    }
    runtime.document.body.innerHTML = '<p id="sentinel">live</p>'

    try {
      expect(
        sanitize('<x-pwn></x-pwn><p onclick=alert(1)>safe</p>', {}, runtime)
      ).toBe('<p>safe</p>')
    } finally {
      parserPrototype.parseFromString = originalParseFromString
    }

    expect(divertedCalls).toBe(0)
    expect(runtime.document.body.innerHTML).toBe('<p id="sentinel">live</p>')
  })

  it('rejects a parser that returns the live runtime document', () => {
    const { runtime } = createRuntime()
    class LiveDocumentParser {
      parseFromString(): Document {
        return runtime.document
      }
    }
    const unsafeRuntime: DOMRuntime = {
      document: runtime.document,
      DOMParser: LiveDocumentParser,
    }
    runtime.document.body.innerHTML = '<p id="sentinel">live</p>'

    expect(
      sanitize('<img src=x onerror=alert(1)>', {}, unsafeRuntime)
    ).toBe('')
    expect(runtime.document.body.innerHTML).toBe('<p id="sentinel">live</p>')
  })

  it('bypasses own-property collisions introduced by untrusted markup hooks', () => {
    const { runtime } = createRuntime()
    const result = sanitize(
      '<p onclick=alert(1)>safe</p><img src=x onerror=alert(2)>',
      {
        hooks: {
          onElement(element) {
            Object.defineProperties(element, {
              attributes: { configurable: true, value: [] },
              hasAttribute: {
                configurable: true,
                value: () => true,
              },
              nextSibling: { configurable: true, value: null },
              parentNode: { configurable: true, value: null },
            })
          },
        },
      },
      runtime
    )

    expect(result).toBe('<p>safe</p><img src="x">')
  })

  it('checks the sibling contract once instead of once per parent', () => {
    const { dom, runtime } = createRuntime()
    const nodePrototype = dom.window.Node.prototype
    const lastChild = Object.getOwnPropertyDescriptor(
      nodePrototype,
      'lastChild'
    )
    if (!lastChild?.get) throw new Error('lastChild is unavailable')

    let reads = 0
    Object.defineProperty(nodePrototype, 'lastChild', {
      ...lastChild,
      get() {
        reads++
        return Reflect.apply(lastChild.get as () => ChildNode | null, this, [])
      },
    })

    try {
      const html = `${'<div>'.repeat(200)}safe${'</div>'.repeat(200)}`
      expect(sanitize(html, {}, runtime)).toBe(html)
    } finally {
      Object.defineProperty(nodePrototype, 'lastChild', lastChild)
    }

    expect(reads).toBe(1)
  })

  it('reuses captured operations for detached documents in one realm', () => {
    const { dom, runtime } = createRuntime()
    const nodePrototype = dom.window.Node.prototype
    const lastChild = Object.getOwnPropertyDescriptor(
      nodePrototype,
      'lastChild'
    )
    if (!lastChild?.get) throw new Error('lastChild is unavailable')

    let reads = 0
    Object.defineProperty(nodePrototype, 'lastChild', {
      ...lastChild,
      get() {
        reads++
        return Reflect.apply(lastChild.get as () => ChildNode | null, this, [])
      },
    })

    let readsAfterParse = 0
    try {
      const fragment = parseHTML('<p>safe</p>', runtime)
      readsAfterParse = reads
      expect(serializeHTML(fragment)).toBe('<p>safe</p>')
      expect(reads).toBe(readsAfterParse)
    } finally {
      Object.defineProperty(nodePrototype, 'lastChild', lastChild)
    }

    expect(readsAfterParse).toBeGreaterThan(0)
  })
})
