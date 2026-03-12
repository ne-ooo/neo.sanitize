import { describe, it, expect } from 'vitest'
import {
  normalizeAttributeName,
  isEventHandler,
  isDataAttribute,
  isAriaAttribute,
  isURLAttribute,
  isForbiddenAttribute,
  isAttributeAllowed,
  validateAttribute,
  filterAllowedAttributes,
} from '../../../src/validators/attributes.js'
import { DEFAULT_ALLOWED_ATTRIBUTES } from '../../../src/utils/constants.js'

describe('normalizeAttributeName', () => {
  it('lowercases uppercase attribute names', () => {
    expect(normalizeAttributeName('ONCLICK')).toBe('onclick')
    expect(normalizeAttributeName('HREF')).toBe('href')
    expect(normalizeAttributeName('CLASS')).toBe('class')
  })

  it('lowercases mixed-case', () => {
    expect(normalizeAttributeName('onClick')).toBe('onclick')
    expect(normalizeAttributeName('DATA-VALUE')).toBe('data-value')
  })

  it('trims whitespace', () => {
    expect(normalizeAttributeName('  href  ')).toBe('href')
  })

  it('returns already-lowercase unchanged', () => {
    expect(normalizeAttributeName('class')).toBe('class')
    expect(normalizeAttributeName('data-id')).toBe('data-id')
  })
})

describe('isEventHandler', () => {
  it('returns true for common event handlers', () => {
    expect(isEventHandler('onclick')).toBe(true)
    expect(isEventHandler('onerror')).toBe(true)
    expect(isEventHandler('onload')).toBe(true)
    expect(isEventHandler('onmouseover')).toBe(true)
    expect(isEventHandler('onsubmit')).toBe(true)
  })

  it('normalizes case before checking', () => {
    expect(isEventHandler('ONCLICK')).toBe(true)
    expect(isEventHandler('OnError')).toBe(true)
    expect(isEventHandler('ONLOAD')).toBe(true)
  })

  it('returns true for any on* attribute (regex fallback)', () => {
    expect(isEventHandler('oncustomevent')).toBe(true)
    expect(isEventHandler('onfoo')).toBe(true)
  })

  it('returns false for normal attributes', () => {
    expect(isEventHandler('class')).toBe(false)
    expect(isEventHandler('href')).toBe(false)
    expect(isEventHandler('id')).toBe(false)
    expect(isEventHandler('title')).toBe(false)
    expect(isEventHandler('data-id')).toBe(false)
  })
})

describe('isDataAttribute', () => {
  it('returns true for data-* attributes', () => {
    expect(isDataAttribute('data-id')).toBe(true)
    expect(isDataAttribute('data-value')).toBe(true)
    expect(isDataAttribute('data-test-foo')).toBe(true)
    expect(isDataAttribute('data-123')).toBe(true)
  })

  it('normalizes case before checking', () => {
    expect(isDataAttribute('DATA-VALUE')).toBe(true)
    expect(isDataAttribute('Data-Id')).toBe(true)
  })

  it('returns false for non-data attributes', () => {
    expect(isDataAttribute('class')).toBe(false)
    expect(isDataAttribute('href')).toBe(false)
    expect(isDataAttribute('id')).toBe(false)
    expect(isDataAttribute('aria-label')).toBe(false)
    expect(isDataAttribute('data')).toBe(false) // just "data" without "-" is not data-*
  })
})

describe('isAriaAttribute', () => {
  it('returns true for aria-* attributes', () => {
    expect(isAriaAttribute('aria-label')).toBe(true)
    expect(isAriaAttribute('aria-hidden')).toBe(true)
    expect(isAriaAttribute('aria-describedby')).toBe(true)
    expect(isAriaAttribute('aria-live')).toBe(true)
  })

  it('normalizes case before checking', () => {
    expect(isAriaAttribute('ARIA-LABEL')).toBe(true)
    expect(isAriaAttribute('Aria-Hidden')).toBe(true)
  })

  it('returns false for non-aria attributes', () => {
    expect(isAriaAttribute('class')).toBe(false)
    expect(isAriaAttribute('href')).toBe(false)
    expect(isAriaAttribute('data-id')).toBe(false)
    expect(isAriaAttribute('role')).toBe(false) // role is not aria-*
  })
})

describe('isURLAttribute', () => {
  it('returns true for URL attributes', () => {
    expect(isURLAttribute('href')).toBe(true)
    expect(isURLAttribute('src')).toBe(true)
    expect(isURLAttribute('action')).toBe(true)
    expect(isURLAttribute('cite')).toBe(true)
    expect(isURLAttribute('poster')).toBe(true)
  })

  it('normalizes case before checking', () => {
    expect(isURLAttribute('HREF')).toBe(true)
    expect(isURLAttribute('SRC')).toBe(true)
  })

  it('returns false for non-URL attributes', () => {
    expect(isURLAttribute('class')).toBe(false)
    expect(isURLAttribute('id')).toBe(false)
    expect(isURLAttribute('title')).toBe(false)
    expect(isURLAttribute('alt')).toBe(false)
    expect(isURLAttribute('onclick')).toBe(false)
  })
})

describe('isForbiddenAttribute', () => {
  it('returns true for onclick', () => {
    expect(isForbiddenAttribute('onclick')).toBe(true)
  })

  it('returns true for onerror', () => {
    expect(isForbiddenAttribute('onerror')).toBe(true)
  })

  it('returns true for formaction', () => {
    expect(isForbiddenAttribute('formaction')).toBe(true)
  })

  it('returns true for any on* attribute (event handler regex)', () => {
    expect(isForbiddenAttribute('oncustom')).toBe(true)
    expect(isForbiddenAttribute('onfoo')).toBe(true)
  })

  it('normalizes case before checking', () => {
    expect(isForbiddenAttribute('ONCLICK')).toBe(true)
    expect(isForbiddenAttribute('OnError')).toBe(true)
  })

  it('returns false for safe attributes', () => {
    expect(isForbiddenAttribute('class')).toBe(false)
    expect(isForbiddenAttribute('href')).toBe(false)
    expect(isForbiddenAttribute('id')).toBe(false)
    expect(isForbiddenAttribute('data-id')).toBe(false)
    expect(isForbiddenAttribute('aria-label')).toBe(false)
  })

  it('uses custom forbiddenAttributes list', () => {
    expect(isForbiddenAttribute('class', ['class', 'id'])).toBe(true)
    expect(isForbiddenAttribute('onclick', ['class'])).toBe(true) // still caught by event handler regex
  })
})

describe('isAttributeAllowed', () => {
  it('allows href on <a> tag', () => {
    expect(isAttributeAllowed('a', 'href')).toBe(true)
  })

  it('allows src on <img> tag', () => {
    expect(isAttributeAllowed('img', 'src')).toBe(true)
  })

  it('denies onclick on any tag', () => {
    expect(isAttributeAllowed('a', 'onclick')).toBe(false)
    expect(isAttributeAllowed('div', 'onclick')).toBe(false)
  })

  it('denies class attribute by default', () => {
    expect(isAttributeAllowed('p', 'class')).toBe(false)
  })

  it('allows class attribute when allowClassAttribute=true', () => {
    expect(isAttributeAllowed('p', 'class', DEFAULT_ALLOWED_ATTRIBUTES, { allowClassAttribute: true })).toBe(true)
  })

  it('denies id attribute by default', () => {
    expect(isAttributeAllowed('p', 'id')).toBe(false)
  })

  it('allows id attribute when allowIdAttribute=true', () => {
    expect(isAttributeAllowed('p', 'id', DEFAULT_ALLOWED_ATTRIBUTES, { allowIdAttribute: true })).toBe(true)
  })

  it('denies style attribute by default', () => {
    expect(isAttributeAllowed('p', 'style')).toBe(false)
  })

  it('allows style attribute when allowStyleAttribute=true', () => {
    expect(isAttributeAllowed('p', 'style', DEFAULT_ALLOWED_ATTRIBUTES, { allowStyleAttribute: true })).toBe(true)
  })

  it('denies data-* attributes by default', () => {
    expect(isAttributeAllowed('div', 'data-id')).toBe(false)
  })

  it('allows data-* attributes when allowDataAttributes=true', () => {
    expect(isAttributeAllowed('div', 'data-id', DEFAULT_ALLOWED_ATTRIBUTES, { allowDataAttributes: true })).toBe(true)
  })

  it('allows aria-* attributes by default (accessibility)', () => {
    expect(isAttributeAllowed('div', 'aria-label')).toBe(true)
    expect(isAttributeAllowed('button', 'aria-hidden')).toBe(true)
  })

  it('denies aria-* attributes when allowAriaAttributes=false', () => {
    expect(isAttributeAllowed('div', 'aria-label', DEFAULT_ALLOWED_ATTRIBUTES, { allowAriaAttributes: false })).toBe(false)
  })

  it('allows all attributes on tags in allowAllAttributes list', () => {
    expect(isAttributeAllowed('code', 'class', DEFAULT_ALLOWED_ATTRIBUTES, { allowAllAttributes: ['code'] })).toBe(true)
    expect(isAttributeAllowed('code', 'data-lang', DEFAULT_ALLOWED_ATTRIBUTES, { allowAllAttributes: ['code'] })).toBe(true)
  })

  it('denies attribute not in allowedAttributes for tag', () => {
    // 'alt' is not in DEFAULT_ALLOWED_ATTRIBUTES for <p>
    expect(isAttributeAllowed('p', 'alt')).toBe(false)
  })
})

describe('validateAttribute', () => {
  it('allows safe href on <a> tag', () => {
    const result = validateAttribute('a', 'href', 'https://example.com')
    expect(result.allowed).toBe(true)
    expect(result.attrName).toBe('href')
    expect(result.attrValue).toBe('https://example.com')
  })

  it('blocks onclick event handler', () => {
    const result = validateAttribute('a', 'onclick', 'alert(1)')
    expect(result.allowed).toBe(false)
    expect(result.reason).toMatch(/event handler/i)
  })

  it('blocks javascript: URL in href', () => {
    const result = validateAttribute('a', 'href', 'javascript:alert(1)')
    expect(result.allowed).toBe(false)
    expect(result.reason).toMatch(/dangerous|protocol/i)
  })

  it('blocks data: URL in src', () => {
    const result = validateAttribute('img', 'src', 'data:text/html,<script>alert(1)</script>')
    expect(result.allowed).toBe(false)
    expect(result.reason).toMatch(/dangerous|protocol/i)
  })

  it('allows safe src on <img>', () => {
    const result = validateAttribute('img', 'src', 'https://example.com/image.png')
    expect(result.allowed).toBe(true)
  })

  it('blocks attribute not in allowedAttributes for tag', () => {
    const result = validateAttribute('p', 'onclick', 'foo()')
    expect(result.allowed).toBe(false)
  })

  it('normalizes attrName in result', () => {
    const result = validateAttribute('a', 'HREF', 'https://example.com')
    expect(result.allowed).toBe(true)
    expect(result.attrName).toBe('href')
  })

  it('blocks formaction attribute', () => {
    const result = validateAttribute('a', 'formaction', 'https://evil.com')
    expect(result.allowed).toBe(false)
    // BUG-7 fix: formaction is correctly identified as "Forbidden attribute"
    // (not "Event handler attribute") since it's a form hijacking vector, not an event handler
    expect(result.reason).toContain('Forbidden attribute')
  })

  it('allows relative URL in href', () => {
    const result = validateAttribute('a', 'href', '/path/to/page')
    expect(result.allowed).toBe(true)
  })
})

describe('filterAllowedAttributes', () => {
  it('keeps only allowed attributes for tag', () => {
    const attrs = { href: 'https://example.com', onclick: 'alert(1)', title: 'Hello' }
    const result = filterAllowedAttributes('a', attrs)
    expect(result['href']).toBe('https://example.com')
    expect(result['title']).toBe('Hello')
    expect(result['onclick']).toBeUndefined()
  })

  it('strips javascript: URL from href', () => {
    const attrs = { href: 'javascript:alert(1)' }
    const result = filterAllowedAttributes('a', attrs)
    expect(result['href']).toBeUndefined()
  })

  it('returns empty object when all attributes are forbidden', () => {
    const attrs = { onclick: 'foo()', onerror: 'bar()' }
    const result = filterAllowedAttributes('p', attrs)
    expect(Object.keys(result)).toHaveLength(0)
  })

  it('keeps allowed attributes for img tag', () => {
    const attrs = { src: 'https://example.com/img.png', alt: 'Image', onclick: 'bad()' }
    const result = filterAllowedAttributes('img', attrs)
    expect(result['src']).toBe('https://example.com/img.png')
    expect(result['alt']).toBe('Image')
    expect(result['onclick']).toBeUndefined()
  })

  it('allows class when allowClassAttribute=true', () => {
    const attrs = { class: 'highlight', onclick: 'bad()' }
    const result = filterAllowedAttributes('p', attrs, DEFAULT_ALLOWED_ATTRIBUTES, { allowClassAttribute: true })
    expect(result['class']).toBe('highlight')
    expect(result['onclick']).toBeUndefined()
  })

  it('handles empty attributes object', () => {
    expect(filterAllowedAttributes('p', {})).toEqual({})
  })
})
