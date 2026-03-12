/**
 * Protocol Handler XSS Vector Tests
 *
 * Tests sanitization of dangerous URL protocols:
 * - javascript: URIs
 * - data: URIs
 * - vbscript: URIs
 * - file: URIs
 * - about: URIs
 */

import { describe, it, expect } from 'vitest'
import { sanitize } from '../../../src/core/sanitizer.js'

describe('Protocol Handler XSS Vectors', () => {
  describe('javascript: protocol (most common)', () => {
    it('should remove javascript: from href', () => {
      const html = '<a href="javascript:alert(\'XSS\')">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a>Click</a>')
    })

    it('should remove javascript: with uppercase', () => {
      const html = '<a href="JAVASCRIPT:alert(\'XSS\')">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a>Click</a>')
    })

    it('should remove javascript: with mixed case', () => {
      const html = '<a href="JaVaScRiPt:alert(\'XSS\')">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a>Click</a>')
    })

    it('should remove javascript: with whitespace', () => {
      const html = '<a href="  javascript:alert(\'XSS\')">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a>Click</a>')
    })

    it('should remove javascript: from img src', () => {
      const html = '<img src="javascript:alert(\'XSS\')">'
      const result = sanitize(html)
      expect(result).toBe('<img>')
    })

    it('should allow safe href after removing javascript:', () => {
      const html = '<a href="https://example.com">Safe</a><a href="javascript:alert(1)">Unsafe</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="https://example.com">Safe</a><a>Unsafe</a>')
    })
  })

  describe('data: protocol', () => {
    it('should remove data: URI from href', () => {
      const html = '<a href="data:text/html,<script>alert(\'XSS\')</script>">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a>Click</a>')
    })

    it('should remove data: URI from img src', () => {
      const html = '<img src="data:text/html,<script>alert(\'XSS\')</script>">'
      const result = sanitize(html)
      expect(result).toBe('<img>')
    })

    it('should remove data: with base64 encoding', () => {
      const html = '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a>Click</a>')
    })

    it('should remove data: with uppercase', () => {
      const html = '<a href="DATA:text/html,<script>alert(1)</script>">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a>Click</a>')
    })
  })

  describe('vbscript: protocol (legacy IE)', () => {
    it('should remove vbscript: from href', () => {
      const html = '<a href="vbscript:msgbox(\'XSS\')">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a>Click</a>')
    })

    it('should remove vbscript: with uppercase', () => {
      const html = '<a href="VBSCRIPT:msgbox(\'XSS\')">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a>Click</a>')
    })
  })

  describe('file: protocol (local file access)', () => {
    it('should remove file: from href', () => {
      const html = '<a href="file:///etc/passwd">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a>Click</a>')
    })

    it('should remove file: with uppercase', () => {
      const html = '<a href="FILE:///etc/passwd">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a>Click</a>')
    })
  })

  describe('about: protocol (browser internals)', () => {
    it('should remove about: from href', () => {
      const html = '<a href="about:blank">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a>Click</a>')
    })
  })

  describe('Safe protocols should be allowed', () => {
    it('should allow http: protocol', () => {
      const html = '<a href="http://example.com">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="http://example.com">Click</a>')
    })

    it('should allow https: protocol', () => {
      const html = '<a href="https://example.com">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="https://example.com">Click</a>')
    })

    it('should allow mailto: protocol', () => {
      const html = '<a href="mailto:test@example.com">Email</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="mailto:test@example.com">Email</a>')
    })

    it('should allow tel: protocol', () => {
      const html = '<a href="tel:+1234567890">Call</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="tel:+1234567890">Call</a>')
    })

    it('should allow ftp: protocol', () => {
      const html = '<a href="ftp://example.com/file.txt">Download</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="ftp://example.com/file.txt">Download</a>')
    })

    it('should allow ftps: protocol', () => {
      const html = '<a href="ftps://example.com/file.txt">Download</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="ftps://example.com/file.txt">Download</a>')
    })
  })

  describe('Relative URLs should be allowed', () => {
    it('should allow path-relative URLs', () => {
      const html = '<a href="/path/to/page">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="/path/to/page">Click</a>')
    })

    it('should allow relative URLs', () => {
      const html = '<a href="page.html">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="page.html">Click</a>')
    })

    it('should allow parent directory URLs', () => {
      const html = '<a href="../page.html">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="../page.html">Click</a>')
    })

    it('should allow fragment URLs', () => {
      const html = '<a href="#section">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="#section">Click</a>')
    })

    it('should allow query string URLs', () => {
      const html = '<a href="?page=2">Next</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="?page=2">Next</a>')
    })

    it('should allow protocol-relative URLs', () => {
      const html = '<a href="//example.com">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="//example.com">Click</a>')
    })
  })

  describe('Protocol in other URL attributes', () => {
    it('should remove javascript: from img src', () => {
      const html = '<img src="javascript:alert(1)">'
      const result = sanitize(html)
      expect(result).toBe('<img>')
    })

    it('should allow safe img src', () => {
      const html = '<img src="https://example.com/image.jpg">'
      const result = sanitize(html)
      expect(result).toBe('<img src="https://example.com/image.jpg">')
    })

    it('should allow relative img src', () => {
      const html = '<img src="/images/photo.jpg">'
      const result = sanitize(html)
      expect(result).toBe('<img src="/images/photo.jpg">')
    })

    it('should remove javascript: from form action (if form was allowed)', () => {
      const html = '<form action="javascript:alert(1)"></form>'
      const result = sanitize(html)
      // form is not allowed, so entire tag is removed
      expect(result).toBe('')
    })
  })

  describe('Edge cases and obfuscation attempts', () => {
    it('should handle javascript: with HTML entities', () => {
      const html = '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">Click</a>'
      const result = sanitize(html)
      // Browser decodes entities before DOMParser sees them
      expect(result).toBe('<a>Click</a>')
    })

    it('should handle javascript: with tabs and newlines', () => {
      const html = '<a href="java\nscript:alert(1)">Click</a>'
      const result = sanitize(html)
      // Browser normalizes whitespace
      expect(result).not.toContain('java')
    })

    it('should handle empty href', () => {
      const html = '<a href="">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="">Click</a>')
    })

    it('should handle missing href value', () => {
      const html = '<a href>Click</a>'
      const result = sanitize(html)
      // Browser normalizes missing attribute value to empty string
      expect(result).toBe('<a href="">Click</a>')
    })
  })

  describe('Multiple dangerous URLs in same HTML', () => {
    it('should remove all javascript: URIs', () => {
      const html = `
        <a href="javascript:alert(1)">Link 1</a>
        <a href="javascript:alert(2)">Link 2</a>
        <img src="javascript:alert(3)">
      `
      const result = sanitize(html)
      expect(result).not.toContain('javascript:')
      expect(result).toContain('Link 1')
      expect(result).toContain('Link 2')
    })

    it('should mix safe and unsafe protocols correctly', () => {
      const html = `
        <a href="https://safe.com">Safe 1</a>
        <a href="javascript:alert(1)">Unsafe</a>
        <a href="mailto:test@example.com">Safe 2</a>
      `
      const result = sanitize(html)
      expect(result).toContain('https://safe.com')
      expect(result).toContain('mailto:test@example.com')
      expect(result).not.toContain('javascript:')
    })
  })
})
