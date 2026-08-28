import { expect } from 'vitest'
import type {
  DOMRuntime,
  HTMLInsertionContext,
} from '../../src/types.js'
import { parseHTML } from '../../src/core/parser.js'
import { isDangerousTag } from '../../src/validators/tags.js'
import { isSafeURLAttributeValue } from '../../src/validators/protocols.js'
import { URL_ATTRIBUTES } from '../../src/utils/constants.js'

const HTML_NAMESPACE = 'http://www.w3.org/1999/xhtml'
const URL_ATTRIBUTE_SET = new Set(URL_ATTRIBUTES)
const PARSER_CONTEXT_ATTRIBUTES = new Set([
  'is',
  'shadowrootclonable',
  'shadowrootdelegatesfocus',
  'shadowrootmode',
  'shadowrootserializable',
  'srcdoc',
])

export function assertHTMLSecurityInvariants(
  html: string,
  runtime?: DOMRuntime,
  insertionContext: HTMLInsertionContext = 'body'
): void {
  const fragment = parseHTML(html, runtime, insertionContext)
  const elements = Array.from(fragment.querySelectorAll('*'))

  for (const element of elements) {
    const tagName = element.localName.toLowerCase()

    expect(element.namespaceURI, `${tagName} must use the HTML namespace`).toBe(
      HTML_NAMESPACE
    )
    expect(isDangerousTag(tagName), `${tagName} must not be active`).toBe(false)
    expect(tagName.includes('-'), `${tagName} must not be a custom element`).toBe(
      false
    )

    for (const attribute of Array.from(element.attributes)) {
      const attributeName = attribute.name.toLowerCase()

      expect(
        attributeName.startsWith('on'),
        `${attributeName} must not be an event handler`
      ).toBe(false)
      expect(
        PARSER_CONTEXT_ATTRIBUTES.has(attributeName),
        `${attributeName} must not create a parsing context`
      ).toBe(false)
      expect(attributeName, 'inline style must not survive the default policy').not.toBe(
        'style'
      )

      if (URL_ATTRIBUTE_SET.has(attributeName)) {
        expect(
          isSafeURLAttributeValue(attributeName, attribute.value),
          `${attributeName} must use a safe protocol`
        ).toBe(true)
      }
    }
  }
}
