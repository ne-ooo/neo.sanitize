import { describe, it, expect } from 'vitest'
import {
  normalizeTagName,
  isTagAllowed,
  isDangerousTag,
  validateTag,
  filterAllowedTags,
  getDangerousTags,
  DANGEROUS_TAGS,
} from '../../../src/validators/tags.js'
import { DEFAULT_ALLOWED_TAGS } from '../../../src/utils/constants.js'

describe('normalizeTagName', () => {
  it('lowercases uppercase tag names', () => {
    expect(normalizeTagName('DIV')).toBe('div')
    expect(normalizeTagName('SCRIPT')).toBe('script')
    expect(normalizeTagName('P')).toBe('p')
  })

  it('lowercases mixed-case tag names', () => {
    expect(normalizeTagName('Script')).toBe('script')
    expect(normalizeTagName('sTrOnG')).toBe('strong')
  })

  it('trims surrounding whitespace', () => {
    expect(normalizeTagName('  div  ')).toBe('div')
    expect(normalizeTagName('\tscript\n')).toBe('script')
  })

  it('returns already-lowercase tags unchanged', () => {
    expect(normalizeTagName('p')).toBe('p')
    expect(normalizeTagName('span')).toBe('span')
  })
})

describe('isTagAllowed', () => {
  it('returns true for tags in DEFAULT_ALLOWED_TAGS', () => {
    expect(isTagAllowed('p')).toBe(true)
    expect(isTagAllowed('div')).toBe(true)
    expect(isTagAllowed('a')).toBe(true)
    expect(isTagAllowed('strong')).toBe(true)
    expect(isTagAllowed('img')).toBe(true)
  })

  it('returns false for script tag', () => {
    expect(isTagAllowed('script')).toBe(false)
  })

  it('returns false for iframe tag', () => {
    expect(isTagAllowed('iframe')).toBe(false)
  })

  it('returns false for style tag', () => {
    expect(isTagAllowed('style')).toBe(false)
  })

  it('normalizes case before checking', () => {
    expect(isTagAllowed('DIV')).toBe(true)
    expect(isTagAllowed('SCRIPT')).toBe(false)
    expect(isTagAllowed('P')).toBe(true)
  })

  it('uses custom allowedTags list', () => {
    expect(isTagAllowed('p', ['p', 'span'])).toBe(true)
    expect(isTagAllowed('div', ['p', 'span'])).toBe(false)
    expect(isTagAllowed('script', ['p', 'script'])).toBe(true)
  })

  it('returns false for unknown tags', () => {
    expect(isTagAllowed('unknown-element')).toBe(false)
    expect(isTagAllowed('xyz')).toBe(false)
  })
})

describe('isDangerousTag', () => {
  it('returns true for all dangerous tags', () => {
    for (const tag of DANGEROUS_TAGS) {
      expect(isDangerousTag(tag), `${tag} should be dangerous`).toBe(true)
    }
  })

  it('returns true for specific dangerous tags', () => {
    expect(isDangerousTag('script')).toBe(true)
    expect(isDangerousTag('iframe')).toBe(true)
    expect(isDangerousTag('object')).toBe(true)
    expect(isDangerousTag('embed')).toBe(true)
    expect(isDangerousTag('style')).toBe(true)
    expect(isDangerousTag('form')).toBe(true)
    expect(isDangerousTag('base')).toBe(true)
    expect(isDangerousTag('meta')).toBe(true)
    expect(isDangerousTag('link')).toBe(true)
  })

  it('normalizes case before checking', () => {
    expect(isDangerousTag('SCRIPT')).toBe(true)
    expect(isDangerousTag('Script')).toBe(true)
    expect(isDangerousTag('IFRAME')).toBe(true)
  })

  it('returns false for safe tags', () => {
    expect(isDangerousTag('p')).toBe(false)
    expect(isDangerousTag('div')).toBe(false)
    expect(isDangerousTag('strong')).toBe(false)
    expect(isDangerousTag('img')).toBe(false)
    expect(isDangerousTag('a')).toBe(false)
  })
})

describe('validateTag', () => {
  it('returns allowed=true for safe tags', () => {
    const result = validateTag('p')
    expect(result.allowed).toBe(true)
    expect(result.tagName).toBe('p')
    expect(result.reason).toBeUndefined()
  })

  it('normalizes tagName in result', () => {
    const result = validateTag('DIV')
    expect(result.allowed).toBe(true)
    expect(result.tagName).toBe('div')
  })

  it('returns allowed=false for dangerous tags with specific reason', () => {
    const result = validateTag('script')
    expect(result.allowed).toBe(false)
    expect(result.tagName).toBe('script')
    expect(result.reason).toMatch(/dangerous/i)
  })

  it('returns allowed=false for iframe with reason', () => {
    const result = validateTag('iframe')
    expect(result.allowed).toBe(false)
    expect(result.reason).toMatch(/dangerous/i)
  })

  it('returns allowed=false for tags not in allowed list', () => {
    const result = validateTag('canvas')
    expect(result.allowed).toBe(false)
    expect(result.tagName).toBe('canvas')
    expect(result.reason).toBeTruthy()
  })

  it('uses custom allowedTags list', () => {
    const result = validateTag('DIV', ['div', 'span'])
    expect(result.allowed).toBe(true)
    expect(result.tagName).toBe('div')
  })

  it('marks tag not in custom allowed list as not allowed', () => {
    const result = validateTag('p', ['div', 'span'])
    expect(result.allowed).toBe(false)
    expect(result.tagName).toBe('p')
  })
})

describe('filterAllowedTags', () => {
  it('keeps only allowed tags', () => {
    const result = filterAllowedTags(['p', 'script', 'div'])
    expect(result).toContain('p')
    expect(result).toContain('div')
    expect(result).not.toContain('script')
  })

  it('normalizes tag names in output', () => {
    const result = filterAllowedTags(['P', 'DIV', 'SCRIPT'])
    expect(result).toContain('p')
    expect(result).toContain('div')
    expect(result).not.toContain('script')
  })

  it('returns empty array when no tags are allowed', () => {
    const result = filterAllowedTags(['script', 'iframe', 'style'])
    expect(result).toHaveLength(0)
  })

  it('returns all tags when all are allowed', () => {
    const result = filterAllowedTags(['p', 'div', 'strong'])
    expect(result).toContain('p')
    expect(result).toContain('div')
    expect(result).toContain('strong')
  })

  it('uses custom allowedTags list', () => {
    const result = filterAllowedTags(['SCRIPT', 'DIV', 'IFRAME'], ['div', 'span'])
    expect(result).toEqual(['div'])
  })

  it('handles empty input', () => {
    expect(filterAllowedTags([])).toEqual([])
  })
})

describe('getDangerousTags', () => {
  it('returns only dangerous tags from mixed list', () => {
    const result = getDangerousTags(['p', 'script', 'div', 'iframe'])
    expect(result).toContain('script')
    expect(result).toContain('iframe')
    expect(result).not.toContain('p')
    expect(result).not.toContain('div')
  })

  it('normalizes tag names in output', () => {
    const result = getDangerousTags(['SCRIPT', 'IFRAME', 'P'])
    expect(result).toContain('script')
    expect(result).toContain('iframe')
    expect(result).not.toContain('p')
  })

  it('returns empty array when no dangerous tags', () => {
    const result = getDangerousTags(['p', 'div', 'strong', 'a'])
    expect(result).toHaveLength(0)
  })

  it('returns all items when all are dangerous', () => {
    const result = getDangerousTags(['script', 'iframe', 'object', 'embed'])
    expect(result).toHaveLength(4)
  })

  it('handles empty input', () => {
    expect(getDangerousTags([])).toEqual([])
  })
})

describe('DANGEROUS_TAGS constant', () => {
  it('is a non-empty readonly array', () => {
    expect(DANGEROUS_TAGS.length).toBeGreaterThan(0)
  })

  it('contains the key dangerous tags', () => {
    expect(DANGEROUS_TAGS).toContain('script')
    expect(DANGEROUS_TAGS).toContain('iframe')
    expect(DANGEROUS_TAGS).toContain('object')
    expect(DANGEROUS_TAGS).toContain('embed')
    expect(DANGEROUS_TAGS).toContain('style')
    expect(DANGEROUS_TAGS).toContain('form')
    expect(DANGEROUS_TAGS).toContain('base')
    expect(DANGEROUS_TAGS).toContain('meta')
  })

  it('does not contain safe tags', () => {
    expect(DANGEROUS_TAGS).not.toContain('p')
    expect(DANGEROUS_TAGS).not.toContain('div')
    expect(DANGEROUS_TAGS).not.toContain('strong')
    expect(DANGEROUS_TAGS).not.toContain('a')
  })

  it('has no overlap with DEFAULT_ALLOWED_TAGS', () => {
    const overlap = DANGEROUS_TAGS.filter((t) => DEFAULT_ALLOWED_TAGS.includes(t))
    expect(overlap).toHaveLength(0)
  })
})
