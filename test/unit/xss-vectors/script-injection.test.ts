/**
 * Script Injection XSS Vector Tests
 *
 * Tests sanitization of <script> tag injections in various forms.
 * Covers OWASP XSS Filter Evasion Cheat Sheet vectors.
 */

import { describe, it, expect } from 'vitest'
import { sanitize } from '../../../src/core/sanitizer.js'

describe('Script Injection XSS Vectors', () => {
  describe('Basic <script> tag injection', () => {
    it('should remove basic script tag', () => {
      const html = '<script>alert("XSS")</script>'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove script tag with content', () => {
      const html = '<p>Hello</p><script>alert("XSS")</script><p>World</p>'
      const result = sanitize(html)
      expect(result).toBe('<p>Hello</p><p>World</p>')
    })

    it('should remove script tag and keep surrounding text', () => {
      const html = 'Before<script>alert("XSS")</script>After'
      const result = sanitize(html)
      expect(result).toBe('BeforeAfter')
    })
  })

  describe('Script tag case variations', () => {
    it('should remove uppercase SCRIPT tag', () => {
      const html = '<SCRIPT>alert("XSS")</SCRIPT>'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove mixed case ScRiPt tag', () => {
      const html = '<ScRiPt>alert("XSS")</ScRiPt>'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove script tag with whitespace', () => {
      const html = '<script >alert("XSS")</script>'
      const result = sanitize(html)
      expect(result).toBe('')
    })
  })

  describe('Script tag with attributes', () => {
    it('should remove script tag with type attribute', () => {
      const html = '<script type="text/javascript">alert("XSS")</script>'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove script tag with src attribute', () => {
      const html = '<script src="http://evil.com/xss.js"></script>'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove script tag with multiple attributes', () => {
      const html = '<script type="text/javascript" src="evil.js" async defer></script>'
      const result = sanitize(html)
      expect(result).toBe('')
    })
  })

  describe('Nested script tags', () => {
    it('should remove nested script tags', () => {
      const html = '<div><p><script>alert("XSS")</script></p></div>'
      const result = sanitize(html)
      expect(result).toBe('<div><p></p></div>')
    })

    it('should remove multiple script tags', () => {
      const html = '<script>alert(1)</script><p>Text</p><script>alert(2)</script>'
      const result = sanitize(html)
      expect(result).toBe('<p>Text</p>')
    })
  })

  describe('Script content variations', () => {
    it('should remove script with encoded characters', () => {
      const html = '<script>alert(String.fromCharCode(88,83,83))</script>'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove script with comments inside', () => {
      const html = '<script><!--alert("XSS")//--></script>'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove script with CDATA', () => {
      const html = '<script><![CDATA[alert("XSS")]]></script>'
      const result = sanitize(html)
      expect(result).toBe('')
    })
  })

  describe('Other dangerous executable tags', () => {
    it('should remove iframe tag', () => {
      const html = '<iframe src="http://evil.com"></iframe>'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove object tag', () => {
      const html = '<object data="http://evil.com/xss.swf"></object>'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove embed tag', () => {
      const html = '<embed src="http://evil.com/xss.swf">'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove applet tag', () => {
      const html = '<applet code="XSS.class"></applet>'
      const result = sanitize(html)
      expect(result).toBe('')
    })
  })

  describe('Style tag injection', () => {
    it('should remove style tag', () => {
      const html = '<style>body{background:url("javascript:alert(1)")}</style>'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove style tag with CSS expression', () => {
      const html = '<style>*{x:expression(alert("XSS"))}</style>'
      const result = sanitize(html)
      expect(result).toBe('')
    })
  })

  describe('Link tag injection', () => {
    it('should remove link tag', () => {
      const html = '<link rel="stylesheet" href="http://evil.com/xss.css">'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove link tag with import', () => {
      const html = '<link rel="import" href="http://evil.com/xss.html">'
      const result = sanitize(html)
      expect(result).toBe('')
    })
  })

  describe('Meta tag injection', () => {
    it('should remove meta refresh redirect', () => {
      const html = '<meta http-equiv="refresh" content="0;url=http://evil.com">'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove meta tag', () => {
      const html = '<meta charset="utf-8">'
      const result = sanitize(html)
      expect(result).toBe('')
    })
  })

  describe('Base tag injection', () => {
    it('should remove base tag (URL hijacking)', () => {
      const html = '<base href="http://evil.com/">'
      const result = sanitize(html)
      expect(result).toBe('')
    })
  })
})
