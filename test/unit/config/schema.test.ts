import { describe, it, expect } from 'vitest'
import {
  BASIC_SCHEMA,
  RELAXED_SCHEMA,
  STRICT_SCHEMA,
  getSchema,
  mergeSchema,
} from '../../../src/config/schemas.js'
import { sanitize } from '../../../src/core/sanitizer.js'

describe('BASIC_SCHEMA', () => {
  it('allows text formatting tags', () => {
    expect(BASIC_SCHEMA.allowedTags).toContain('p')
    expect(BASIC_SCHEMA.allowedTags).toContain('strong')
    expect(BASIC_SCHEMA.allowedTags).toContain('em')
    expect(BASIC_SCHEMA.allowedTags).toContain('code')
    expect(BASIC_SCHEMA.allowedTags).toContain('ul')
    expect(BASIC_SCHEMA.allowedTags).toContain('ol')
    expect(BASIC_SCHEMA.allowedTags).toContain('li')
    expect(BASIC_SCHEMA.allowedTags).toContain('a')
  })

  it('does not allow images or tables', () => {
    expect(BASIC_SCHEMA.allowedTags).not.toContain('img')
    expect(BASIC_SCHEMA.allowedTags).not.toContain('table')
    expect(BASIC_SCHEMA.allowedTags).not.toContain('h1')
  })

  it('does not allow class/id/style attributes', () => {
    expect(BASIC_SCHEMA.allowClassAttribute).toBe(false)
    expect(BASIC_SCHEMA.allowIdAttribute).toBe(false)
    expect(BASIC_SCHEMA.allowStyleAttribute).toBe(false)
  })

  it('does not allow data-* attributes', () => {
    expect(BASIC_SCHEMA.allowDataAttributes).toBe(false)
  })

  it('only allows http and https protocols', () => {
    expect(BASIC_SCHEMA.allowedProtocols).toContain('http')
    expect(BASIC_SCHEMA.allowedProtocols).toContain('https')
    expect(BASIC_SCHEMA.allowedProtocols).not.toContain('ftp')
    expect(BASIC_SCHEMA.allowedProtocols).not.toContain('mailto')
  })

  it('strips script tags when used with sanitize()', () => {
    const result = sanitize('<script>alert(1)</script><p>Hello</p>', BASIC_SCHEMA)
    expect(result).not.toContain('<script>')
    expect(result).toContain('<p>Hello</p>')
  })

  it('strips img tags when used with sanitize()', () => {
    const result = sanitize('<img src="x" onerror="alert(1)"><p>Safe</p>', BASIC_SCHEMA)
    expect(result).not.toContain('<img')
    expect(result).toContain('<p>Safe</p>')
  })
})

describe('RELAXED_SCHEMA', () => {
  it('allows all default tags including images and tables', () => {
    expect(RELAXED_SCHEMA.allowedTags).toContain('img')
    expect(RELAXED_SCHEMA.allowedTags).toContain('table')
    expect(RELAXED_SCHEMA.allowedTags).toContain('h1')
    expect(RELAXED_SCHEMA.allowedTags).toContain('p')
    expect(RELAXED_SCHEMA.allowedTags).toContain('a')
  })

  it('allows class attribute', () => {
    expect(RELAXED_SCHEMA.allowClassAttribute).toBe(true)
  })

  it('allows data-* attributes', () => {
    expect(RELAXED_SCHEMA.allowDataAttributes).toBe(true)
  })

  it('does not allow id attribute (DOM clobbering risk)', () => {
    expect(RELAXED_SCHEMA.allowIdAttribute).toBe(false)
  })

  it('does not allow style attribute (CSS injection risk)', () => {
    expect(RELAXED_SCHEMA.allowStyleAttribute).toBe(false)
  })

  it('allows more protocols than BASIC_SCHEMA', () => {
    expect(RELAXED_SCHEMA.allowedProtocols).toContain('https')
    expect(RELAXED_SCHEMA.allowedProtocols).toContain('http')
    expect(RELAXED_SCHEMA.allowedProtocols).toContain('mailto')
    expect(RELAXED_SCHEMA.allowedProtocols).toContain('ftp')
  })

  it('still strips javascript: URLs', () => {
    const result = sanitize('<a href="javascript:alert(1)">Click</a>', RELAXED_SCHEMA)
    expect(result).not.toContain('javascript:')
  })
})

describe('STRICT_SCHEMA', () => {
  it('allows no tags (empty array)', () => {
    expect(STRICT_SCHEMA.allowedTags).toHaveLength(0)
  })

  it('allows no attributes', () => {
    expect(Object.keys(STRICT_SCHEMA.allowedAttributes)).toHaveLength(0)
  })

  it('allows no protocols', () => {
    expect(STRICT_SCHEMA.allowedProtocols).toHaveLength(0)
  })

  it('has stripTags=true', () => {
    expect(STRICT_SCHEMA.stripTags).toBe(true)
  })

  it('has keepTextContent=true', () => {
    expect(STRICT_SCHEMA.keepTextContent).toBe(true)
  })

  it('disables all special attributes', () => {
    expect(STRICT_SCHEMA.allowDataAttributes).toBe(false)
    expect(STRICT_SCHEMA.allowAriaAttributes).toBe(false)
    expect(STRICT_SCHEMA.allowClassAttribute).toBe(false)
    expect(STRICT_SCHEMA.allowIdAttribute).toBe(false)
    expect(STRICT_SCHEMA.allowStyleAttribute).toBe(false)
  })

  it('strips all HTML when used with sanitize()', () => {
    const result = sanitize('<p><strong>Bold</strong> and <script>alert(1)</script></p>', STRICT_SCHEMA)
    expect(result).not.toContain('<p>')
    expect(result).not.toContain('<strong>')
    expect(result).not.toContain('<script>')
  })
})

describe('getSchema', () => {
  it('returns BASIC_SCHEMA for "BASIC"', () => {
    const schema = getSchema('BASIC')
    expect(schema).toBe(BASIC_SCHEMA)
  })

  it('returns RELAXED_SCHEMA for "RELAXED"', () => {
    const schema = getSchema('RELAXED')
    expect(schema).toBe(RELAXED_SCHEMA)
  })

  it('returns STRICT_SCHEMA for "STRICT"', () => {
    const schema = getSchema('STRICT')
    expect(schema).toBe(STRICT_SCHEMA)
  })
})

describe('mergeSchema', () => {
  it('returns BASIC_SCHEMA merged with custom options', () => {
    const merged = mergeSchema('BASIC', { allowDataAttributes: true })
    // Base is BASIC (no data-*), but override enables it
    expect(merged.allowDataAttributes).toBe(true)
    // Other BASIC settings preserved
    expect(merged.allowClassAttribute).toBe(false)
    expect(merged.allowStyleAttribute).toBe(false)
  })

  it('can override allowedTags', () => {
    const merged = mergeSchema('BASIC', { allowedTags: ['p', 'div', 'img'] })
    expect(merged.allowedTags).toContain('img')
    expect(merged.allowedTags).toContain('p')
    expect(merged.allowedTags).toContain('div')
    // BASIC doesn't have img, but we added it
    expect(BASIC_SCHEMA.allowedTags).not.toContain('img')
  })

  it('can override allowedProtocols', () => {
    const merged = mergeSchema('BASIC', { allowedProtocols: ['https', 'mailto'] })
    expect(merged.allowedProtocols).toContain('mailto')
    // BASIC doesn't have mailto
    expect(BASIC_SCHEMA.allowedProtocols).not.toContain('mailto')
  })

  it('preserves base schema tags when no allowedTags provided', () => {
    const merged = mergeSchema('RELAXED', { allowClassAttribute: false })
    // Should still have RELAXED tags
    expect(merged.allowedTags).toContain('img')
    expect(merged.allowedTags).toContain('table')
    // But class is now disabled
    expect(merged.allowClassAttribute).toBe(false)
  })

  it('STRICT merged with allowedTags adds them', () => {
    const merged = mergeSchema('STRICT', { allowedTags: ['p', 'strong'] })
    expect(merged.allowedTags).toContain('p')
    expect(merged.allowedTags).toContain('strong')
  })

  it('does not mutate the original schema', () => {
    const before = [...BASIC_SCHEMA.allowedTags]
    mergeSchema('BASIC', { allowedTags: ['p', 'div', 'img'] })
    expect(BASIC_SCHEMA.allowedTags).toEqual(before)
  })
})

describe('Schema security level differences with same payload', () => {
  const xssPayload = '<p>Hello <script>alert(1)</script> <img src="x" onerror="alert(2)"> world</p>'

  it('BASIC: keeps p, strips script and img', () => {
    const result = sanitize(xssPayload, BASIC_SCHEMA)
    expect(result).toContain('<p>')
    expect(result).not.toContain('<script>')
    expect(result).not.toContain('<img')
    expect(result).toContain('Hello')
    expect(result).toContain('world')
  })

  it('RELAXED: keeps p and img (safe src), strips script', () => {
    const result = sanitize(xssPayload, RELAXED_SCHEMA)
    expect(result).toContain('<p>')
    expect(result).not.toContain('<script>')
    expect(result).not.toContain('onerror')
  })

  it('STRICT: strips everything, keeps only text', () => {
    const result = sanitize(xssPayload, STRICT_SCHEMA)
    expect(result).not.toContain('<p>')
    expect(result).not.toContain('<script>')
    expect(result).not.toContain('<img')
  })
})
