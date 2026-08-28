import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { JSDOM } from 'jsdom'
import {
  sanitizeToTrustedHTML,
  type DOMRuntime,
  type TrustedTypePolicyLike,
} from '../../../src/index.js'

const trustedHTMLBrand = Symbol('TrustedHTML')

class FakeTrustedHTML {
  readonly [trustedHTMLBrand] = true

  constructor(private readonly value: string) {}

  toString(): string {
    return this.value
  }
}

const factory = {
  isHTML(value: unknown): boolean {
    return (
      typeof value === 'object' &&
      value !== null &&
      trustedHTMLBrand in value
    )
  },
}

let originalTrustedTypes: PropertyDescriptor | undefined

beforeEach(() => {
  originalTrustedTypes = Object.getOwnPropertyDescriptor(
    globalThis,
    'trustedTypes'
  )
  Object.defineProperty(globalThis, 'trustedTypes', {
    configurable: true,
    value: factory,
  })
})

afterEach(() => {
  if (originalTrustedTypes) {
    Object.defineProperty(globalThis, 'trustedTypes', originalTrustedTypes)
  } else {
    Reflect.deleteProperty(globalThis, 'trustedTypes')
  }
})

function createPolicy(
  convert: (input: string) => FakeTrustedHTML = (input) =>
    new FakeTrustedHTML(input)
): TrustedTypePolicyLike<FakeTrustedHTML> {
  return { createHTML: convert }
}

describe('Trusted Types integration', () => {
  it('returns TrustedHTML containing only sanitized output', () => {
    const calls: string[] = []
    const policy = createPolicy((input) => {
      calls.push(input)
      return new FakeTrustedHTML(input)
    })

    const clean = sanitizeToTrustedHTML(
      '<script>alert(1)</script><p onclick=alert(2)>safe</p>',
      policy
    )

    expect(factory.isHTML(clean)).toBe(true)
    expect(String(clean)).toBe('<p>safe</p>')
    expect(calls).toContain(
      '<script>alert(1)</script><p onclick=alert(2)>safe</p>'
    )
    expect(calls.at(-1)).toBe('<p>safe</p>')
  })

  it('uses TrustedHTML for contextual parsing and mXSS stabilization', () => {
    const clean = sanitizeToTrustedHTML(
      '<tr><td><math><mtext>bad</mtext></math>' +
        '<img src=x onerror=alert(1)>safe</td></tr>',
      createPolicy(),
      { insertionContext: 'table', detectMXSS: true }
    )

    expect(String(clean)).toBe(
      '<tbody><tr><td><img src="x">safe</td></tr></tbody>'
    )
  })

  it('rejects fragment output because TrustedHTML is a string sink type', () => {
    expect(() =>
      sanitizeToTrustedHTML('<p>safe</p>', createPolicy(), {
        returnString: false,
      })
    ).toThrow(/does not support returnString: false/)
  })

  it('rejects policies that transform their input', () => {
    const policy = createPolicy(
      (input) => new FakeTrustedHTML(`${input}<p>injected</p>`)
    )

    expect(() => sanitizeToTrustedHTML('<p>safe</p>', policy)).toThrow(
      /must preserve its input unchanged/
    )
  })

  it('rejects values that are not recognized as TrustedHTML', () => {
    const policy = {
      createHTML(input: string) {
        return { toString: () => input }
      },
    }

    expect(() => sanitizeToTrustedHTML('<p>safe</p>', policy)).toThrow(
      /did not return TrustedHTML/
    )
  })

  it('fails clearly when Trusted Types are unavailable', () => {
    Reflect.deleteProperty(globalThis, 'trustedTypes')

    expect(() =>
      sanitizeToTrustedHTML('<p>safe</p>', createPolicy())
    ).toThrow(/Trusted Types are not available/)
  })

  it('validates against an explicit runtime realm', () => {
    const dom = new JSDOM('<!doctype html><html><body></body></html>')
    const runtimeBrand = Symbol('RuntimeTrustedHTML')
    class RuntimeTrustedHTML {
      readonly [runtimeBrand] = true

      constructor(private readonly value: string) {}

      toString(): string {
        return this.value
      }
    }
    const runtimeFactory = {
      isHTML(value: unknown): boolean {
        return (
          typeof value === 'object' &&
          value !== null &&
          runtimeBrand in value
        )
      },
    }
    Object.defineProperty(dom.window, 'trustedTypes', {
      configurable: true,
      value: runtimeFactory,
    })
    const runtime: DOMRuntime = {
      document: dom.window.document,
      DOMParser: dom.window.DOMParser,
    }
    const policy: TrustedTypePolicyLike<RuntimeTrustedHTML> = {
      createHTML(input: string): RuntimeTrustedHTML {
        return new RuntimeTrustedHTML(input)
      },
    }

    const clean = sanitizeToTrustedHTML(
      '<img src=x onerror=alert(1)><p>safe</p>',
      policy,
      {},
      runtime
    )

    expect(runtimeFactory.isHTML(clean)).toBe(true)
    expect(factory.isHTML(clean)).toBe(false)
    expect(String(clean)).toBe('<img src="x"><p>safe</p>')
  })
})
