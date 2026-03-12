import { describe, it, expect } from 'vitest'
import {
  getProtocol,
  isProtocolAllowed,
  isDangerousProtocol,
  validateProtocol,
  sanitizeURL,
  isSafeURL,
} from '../../../src/validators/protocols.js'
import { ALLOWED_PROTOCOLS, DANGEROUS_PROTOCOLS } from '../../../src/utils/constants.js'

describe('getProtocol', () => {
  it('extracts https protocol', () => {
    expect(getProtocol('https://example.com')).toBe('https')
  })

  it('extracts http protocol', () => {
    expect(getProtocol('http://example.com')).toBe('http')
  })

  it('extracts javascript protocol', () => {
    expect(getProtocol('javascript:alert(1)')).toBe('javascript')
  })

  it('extracts data protocol', () => {
    expect(getProtocol('data:text/html,<script>alert(1)</script>')).toBe('data')
  })

  it('extracts mailto protocol', () => {
    expect(getProtocol('mailto:user@example.com')).toBe('mailto')
  })

  it('returns null for relative URLs starting with /', () => {
    expect(getProtocol('/path/to/page')).toBeNull()
  })

  it('returns null for relative URLs starting with ./', () => {
    expect(getProtocol('./relative')).toBeNull()
  })

  it('returns null for relative URLs starting with ../', () => {
    expect(getProtocol('../parent')).toBeNull()
  })

  it('returns null for protocol-relative URLs starting with //', () => {
    expect(getProtocol('//example.com')).toBeNull()
  })

  it('returns null for URLs with no protocol', () => {
    expect(getProtocol('justpath')).toBeNull()
  })

  it('trims whitespace before extracting protocol (XSS vector)', () => {
    expect(getProtocol('  javascript:alert(1)')).toBe('javascript')
    expect(getProtocol('\tdata:text/html,xss')).toBe('data')
  })

  it('lowercases protocol names', () => {
    expect(getProtocol('HTTPS://example.com')).toBe('https')
    expect(getProtocol('JavaScript:alert(1)')).toBe('javascript')
  })

  it('returns null for empty string', () => {
    expect(getProtocol('')).toBeNull()
  })
})

describe('isProtocolAllowed', () => {
  it('returns true for allowed protocols', () => {
    expect(isProtocolAllowed('https')).toBe(true)
    expect(isProtocolAllowed('http')).toBe(true)
    expect(isProtocolAllowed('mailto')).toBe(true)
    expect(isProtocolAllowed('tel')).toBe(true)
  })

  it('returns false for javascript protocol', () => {
    expect(isProtocolAllowed('javascript')).toBe(false)
  })

  it('returns false for data protocol', () => {
    expect(isProtocolAllowed('data')).toBe(false)
  })

  it('returns false for vbscript protocol', () => {
    expect(isProtocolAllowed('vbscript')).toBe(false)
  })

  it('returns true for null protocol (relative URLs)', () => {
    expect(isProtocolAllowed(null)).toBe(true)
  })

  it('uses custom allowedProtocols list', () => {
    expect(isProtocolAllowed('https', ['https'])).toBe(true)
    expect(isProtocolAllowed('http', ['https'])).toBe(false)
    expect(isProtocolAllowed('mailto', ['https', 'http'])).toBe(false)
  })
})

describe('isDangerousProtocol', () => {
  it('returns true for all DANGEROUS_PROTOCOLS', () => {
    for (const protocol of DANGEROUS_PROTOCOLS) {
      expect(isDangerousProtocol(protocol), `${protocol} should be dangerous`).toBe(true)
    }
  })

  it('returns true for javascript', () => {
    expect(isDangerousProtocol('javascript')).toBe(true)
  })

  it('returns true for data', () => {
    expect(isDangerousProtocol('data')).toBe(true)
  })

  it('returns true for vbscript', () => {
    expect(isDangerousProtocol('vbscript')).toBe(true)
  })

  it('returns true for about', () => {
    expect(isDangerousProtocol('about')).toBe(true)
  })

  it('returns true for file', () => {
    expect(isDangerousProtocol('file')).toBe(true)
  })

  it('returns false for safe protocols', () => {
    expect(isDangerousProtocol('https')).toBe(false)
    expect(isDangerousProtocol('http')).toBe(false)
    expect(isDangerousProtocol('mailto')).toBe(false)
    expect(isDangerousProtocol('ftp')).toBe(false)
  })

  it('returns false for null (relative URL)', () => {
    expect(isDangerousProtocol(null)).toBe(false)
  })
})

describe('validateProtocol', () => {
  it('returns allowed=true for https URL', () => {
    const result = validateProtocol('https://example.com')
    expect(result.allowed).toBe(true)
    expect(result.protocol).toBe('https')
    expect(result.dangerous).toBe(false)
    expect(result.reason).toBeUndefined()
  })

  it('returns allowed=true for relative URL', () => {
    const result = validateProtocol('/path/to/page')
    expect(result.allowed).toBe(true)
    expect(result.protocol).toBeNull()
    expect(result.dangerous).toBe(false)
  })

  it('returns allowed=false and dangerous=true for javascript:', () => {
    const result = validateProtocol('javascript:alert(1)')
    expect(result.allowed).toBe(false)
    expect(result.protocol).toBe('javascript')
    expect(result.dangerous).toBe(true)
    expect(result.reason).toMatch(/dangerous/i)
  })

  it('returns allowed=false and dangerous=true for data:', () => {
    const result = validateProtocol('data:text/html,<script>alert(1)</script>')
    expect(result.allowed).toBe(false)
    expect(result.dangerous).toBe(true)
  })

  it('returns allowed=false for unknown protocol', () => {
    const result = validateProtocol('custom-scheme://foo')
    expect(result.allowed).toBe(false)
    expect(result.dangerous).toBe(false)
    expect(result.reason).toMatch(/not allowed/i)
  })

  it('uses custom allowedProtocols', () => {
    const result = validateProtocol('mailto:user@example.com', ['https', 'http'])
    expect(result.allowed).toBe(false)
    expect(result.protocol).toBe('mailto')
  })
})

describe('sanitizeURL', () => {
  it('returns safe URLs unchanged', () => {
    expect(sanitizeURL('https://example.com')).toBe('https://example.com')
    expect(sanitizeURL('http://example.com/path?q=1')).toBe('http://example.com/path?q=1')
    expect(sanitizeURL('/relative/path')).toBe('/relative/path')
    expect(sanitizeURL('mailto:user@example.com')).toBe('mailto:user@example.com')
  })

  it('returns empty string for javascript: URL by default', () => {
    expect(sanitizeURL('javascript:alert(1)')).toBe('')
  })

  it('returns empty string for data: URL by default', () => {
    expect(sanitizeURL('data:text/html,xss')).toBe('')
  })

  it('returns custom fallback for dangerous URL', () => {
    expect(sanitizeURL('javascript:alert(1)', undefined, '#')).toBe('#')
    expect(sanitizeURL('data:text/html,xss', undefined, 'about:blank')).toBe('about:blank')
  })

  it('respects custom allowedProtocols', () => {
    expect(sanitizeURL('mailto:user@example.com', ['https', 'http'])).toBe('')
    expect(sanitizeURL('https://example.com', ['https'])).toBe('https://example.com')
  })
})

describe('isSafeURL', () => {
  it('returns true for https URL', () => {
    expect(isSafeURL('https://example.com')).toBe(true)
  })

  it('returns true for http URL', () => {
    expect(isSafeURL('http://example.com')).toBe(true)
  })

  it('returns true for relative URL', () => {
    expect(isSafeURL('/relative/path')).toBe(true)
    expect(isSafeURL('./relative')).toBe(true)
  })

  it('returns true for mailto URL', () => {
    expect(isSafeURL('mailto:user@example.com')).toBe(true)
  })

  it('returns false for javascript: URL', () => {
    expect(isSafeURL('javascript:alert(1)')).toBe(false)
  })

  it('returns false for data: URL', () => {
    expect(isSafeURL('data:text/html,<script>alert(1)</script>')).toBe(false)
  })

  it('returns false for vbscript: URL', () => {
    expect(isSafeURL('vbscript:msgbox(1)')).toBe(false)
  })

  it('returns false for file: URL', () => {
    expect(isSafeURL('file:///etc/passwd')).toBe(false)
  })

  it('handles whitespace-prefixed javascript: (XSS vector)', () => {
    expect(isSafeURL('  javascript:alert(1)')).toBe(false)
  })

  it('respects custom allowedProtocols', () => {
    expect(isSafeURL('mailto:user@example.com', ['https', 'http'])).toBe(false)
    expect(isSafeURL('https://example.com', ['https'])).toBe(true)
  })

  it('returns false for about: URL', () => {
    expect(isSafeURL('about:blank')).toBe(false)
  })
})
