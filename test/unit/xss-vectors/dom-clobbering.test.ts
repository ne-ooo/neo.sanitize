/**
 * DOM Clobbering XSS Vector Tests
 *
 * Tests prevention of DOM clobbering attacks where HTML elements
 * with id/name attributes override critical DOM properties and APIs.
 *
 * References:
 * - https://portswigger.net/web-security/dom-based/dom-clobbering
 * - https://domclob.xyz/domc_wiki/
 */

import { describe, it, expect } from 'vitest'
import { sanitize } from '../../../src/core/sanitizer.js'
import {
  isDangerousId,
  isDangerousName,
  validateDomClobbering,
} from '../../../src/validators/dom-clobbering.js'

describe('DOM Clobbering Prevention', () => {
  describe('Dangerous ID detection', () => {
    it('should detect dangerous Document API ids', () => {
      expect(isDangerousId('createElement')).toBe(true)
      expect(isDangerousId('getElementById')).toBe(true)
      expect(isDangerousId('querySelector')).toBe(true)
      expect(isDangerousId('body')).toBe(true)
      expect(isDangerousId('head')).toBe(true)
      expect(isDangerousId('cookie')).toBe(true)
    })

    it('should detect dangerous Window API ids', () => {
      expect(isDangerousId('window')).toBe(true)
      expect(isDangerousId('document')).toBe(true)
      expect(isDangerousId('location')).toBe(true)
      expect(isDangerousId('navigator')).toBe(true)
      expect(isDangerousId('fetch')).toBe(true)
      expect(isDangerousId('alert')).toBe(true)
    })

    it('should detect dangerous storage API ids', () => {
      expect(isDangerousId('localStorage')).toBe(true)
      expect(isDangerousId('sessionStorage')).toBe(true)
      expect(isDangerousId('indexedDB')).toBe(true)
    })

    it('should detect dangerous framework ids', () => {
      expect(isDangerousId('React')).toBe(true)
      expect(isDangerousId('Vue')).toBe(true)
      expect(isDangerousId('Angular')).toBe(true)
      expect(isDangerousId('jQuery')).toBe(true)
    })

    it('should detect prototype pollution risks', () => {
      expect(isDangerousId('constructor')).toBe(true)
      expect(isDangerousId('prototype')).toBe(true)
      expect(isDangerousId('__proto__')).toBe(true)
      expect(isDangerousId('hasOwnProperty')).toBe(true)
      expect(isDangerousId('toString')).toBe(true)
    })

    it('should be case-insensitive', () => {
      expect(isDangerousId('CREATEELEMENT')).toBe(true)
      expect(isDangerousId('CreateElement')).toBe(true)
      expect(isDangerousId('createElement')).toBe(true)
    })

    it('should allow safe user-defined ids', () => {
      expect(isDangerousId('my-button')).toBe(false)
      expect(isDangerousId('user-profile')).toBe(false)
      expect(isDangerousId('header-nav')).toBe(false)
      expect(isDangerousId('content-area')).toBe(false)
    })
  })

  describe('Dangerous name detection', () => {
    it('should detect dangerous form element names', () => {
      expect(isDangerousName('submit', 'input')).toBe(true)
      expect(isDangerousName('reset', 'button')).toBe(true)
      expect(isDangerousName('action', 'input')).toBe(true)
      expect(isDangerousName('method', 'input')).toBe(true)
      expect(isDangerousName('elements', 'input')).toBe(true)
    })

    it('should detect dangerous API names on form elements', () => {
      expect(isDangerousName('createElement', 'form')).toBe(true)
      expect(isDangerousName('getElementById', 'iframe')).toBe(true)
      expect(isDangerousName('body', 'img')).toBe(true)
    })

    it('should be more lenient for non-form elements', () => {
      // Non-critical names should be allowed on non-form elements
      expect(isDangerousName('submit', 'div')).toBe(false)
      expect(isDangerousName('reset', 'span')).toBe(false)
      expect(isDangerousName('action', 'p')).toBe(false)
    })

    it('should still block critical names on all elements', () => {
      expect(isDangerousName('createElement', 'div')).toBe(true)
      expect(isDangerousName('body', 'span')).toBe(true)
      expect(isDangerousName('document', 'p')).toBe(true)
    })

    it('should allow safe user-defined names', () => {
      expect(isDangerousName('username', 'input')).toBe(false)
      expect(isDangerousName('email', 'input')).toBe(false)
      expect(isDangerousName('password', 'input')).toBe(false)
    })
  })

  describe('validateDomClobbering function', () => {
    it('should block dangerous id attributes by default', () => {
      const result = validateDomClobbering('div', 'id', 'createElement', false)
      expect(result.allowed).toBe(false)
      expect(result.reason).toContain('DOM clobbering')
    })

    it('should block dangerous name attributes by default', () => {
      const result = validateDomClobbering('form', 'name', 'submit', false)
      expect(result.allowed).toBe(false)
      expect(result.reason).toContain('DOM clobbering')
    })

    it('should allow safe id attributes', () => {
      const result = validateDomClobbering('div', 'id', 'my-button', false)
      expect(result.allowed).toBe(true)
    })

    it('should allow when allowDomClobbering is true', () => {
      const result = validateDomClobbering('div', 'id', 'createElement', true)
      expect(result.allowed).toBe(true)
    })

    it('should not validate non-id/name attributes', () => {
      const result = validateDomClobbering('div', 'class', 'createElement', false)
      expect(result.allowed).toBe(true)
    })
  })

  describe('Document API clobbering prevention', () => {
    it('should remove id="createElement"', () => {
      const html = '<div id="createElement">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="createElement"')
      expect(result).toBe('<div>Content</div>')
    })

    it('should remove id="getElementById"', () => {
      const html = '<div id="getElementById">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="getElementById"')
      expect(result).toBe('<div>Content</div>')
    })

    it('should remove id="querySelector"', () => {
      const html = '<div id="querySelector">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="querySelector"')
      expect(result).toBe('<div>Content</div>')
    })

    it('should remove id="body"', () => {
      const html = '<div id="body">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="body"')
      expect(result).toBe('<div>Content</div>')
    })

    it('should remove id="cookie"', () => {
      const html = '<div id="cookie">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="cookie"')
      expect(result).toBe('<div>Content</div>')
    })
  })

  describe('Window API clobbering prevention', () => {
    it('should remove id="window"', () => {
      const html = '<div id="window">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="window"')
      expect(result).toBe('<div>Content</div>')
    })

    it('should remove id="document"', () => {
      const html = '<div id="document">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="document"')
      expect(result).toBe('<div>Content</div>')
    })

    it('should remove id="location"', () => {
      const html = '<div id="location">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="location"')
      expect(result).toBe('<div>Content</div>')
    })

    it('should remove id="fetch"', () => {
      const html = '<div id="fetch">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="fetch"')
      expect(result).toBe('<div>Content</div>')
    })

    it('should remove id="alert"', () => {
      const html = '<div id="alert">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="alert"')
      expect(result).toBe('<div>Content</div>')
    })
  })

  describe('Form API clobbering prevention', () => {
    it('should remove name="submit" from form elements', () => {
      const html = '<a href="#" name="submit">Link</a>'
      const result = sanitize(html, { preventDOMClobbering: true })
      expect(result).not.toContain('name="submit"')
      expect(result).toBe('<a href="#">Link</a>')
    })

    it('should remove name="reset" from form elements', () => {
      const html = '<a href="#" name="reset">Link</a>'
      const result = sanitize(html, { preventDOMClobbering: true })
      expect(result).not.toContain('name="reset"')
      expect(result).toBe('<a href="#">Link</a>')
    })

    it('should remove name="action"', () => {
      const html = '<a href="#" name="action">Link</a>'
      const result = sanitize(html, { preventDOMClobbering: true })
      expect(result).not.toContain('name="action"')
      expect(result).toBe('<a href="#">Link</a>')
    })

    it('should remove name="elements"', () => {
      const html = '<a href="#" name="elements">Link</a>'
      const result = sanitize(html, { preventDOMClobbering: true })
      expect(result).not.toContain('name="elements"')
      expect(result).toBe('<a href="#">Link</a>')
    })
  })

  describe('Prototype pollution prevention', () => {
    it('should remove id="constructor"', () => {
      const html = '<div id="constructor">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="constructor"')
      expect(result).toBe('<div>Content</div>')
    })

    it('should remove id="prototype"', () => {
      const html = '<div id="prototype">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="prototype"')
      expect(result).toBe('<div>Content</div>')
    })

    it('should remove id="__proto__"', () => {
      const html = '<div id="__proto__">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="__proto__"')
      expect(result).toBe('<div>Content</div>')
    })

    it('should remove id="hasOwnProperty"', () => {
      const html = '<div id="hasOwnProperty">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="hasOwnProperty"')
      expect(result).toBe('<div>Content</div>')
    })
  })

  describe('Case insensitivity', () => {
    it('should remove UPPERCASE dangerous ids', () => {
      const html = '<div id="CREATEELEMENT">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('CREATEELEMENT')
      expect(result).toBe('<div>Content</div>')
    })

    it('should remove MixedCase dangerous ids', () => {
      const html = '<div id="CreateElement">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('CreateElement')
      expect(result).toBe('<div>Content</div>')
    })
  })

  describe('Safe id/name attributes', () => {
    it('should allow safe user-defined ids', () => {
      const html = '<div id="my-button">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).toBe('<div id="my-button">Content</div>')
    })

    it('should allow safe user-defined names (when name is allowed)', () => {
      const html = '<a href="#" name="user-link">Link</a>'
      const result = sanitize(html, {
        preventDOMClobbering: true,
        allowedAttributes: { a: ['href', 'title', 'name'] }  // explicitly allow name
      })
      expect(result).toBe('<a href="#" name="user-link">Link</a>')
    })

    it('should allow multiple safe attributes', () => {
      const html = '<a href="#" id="header-nav" title="Navigation">Nav</a>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).toBe('<a href="#" id="header-nav" title="Navigation">Nav</a>')
    })
  })

  describe('preventDOMClobbering option', () => {
    it('should block DOM clobbering when preventDOMClobbering=true', () => {
      const html = '<div id="createElement">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="createElement"')
    })

    it('should allow DOM clobbering when preventDOMClobbering=false (unsafe!)', () => {
      const html = '<div id="createElement">Content</div>'
      const result = sanitize(html, { preventDOMClobbering: false, allowIdAttribute: true })
      expect(result).toBe('<div id="createElement">Content</div>')
    })

    it('should default to false (allow clobbering by default)', () => {
      const html = '<div id="createElement">Content</div>'
      const result = sanitize(html, { allowIdAttribute: true })
      // Default is to allow (for backward compatibility)
      expect(result).toBe('<div id="createElement">Content</div>')
    })
  })

  describe('Real-world DOM clobbering attacks', () => {
    it('should prevent form.createElement clobbering', () => {
      // This would make document.createElement unusable
      const html = '<a href="#" name="createElement">Link</a>'
      const result = sanitize(html, { preventDOMClobbering: true })
      expect(result).not.toContain('name="createElement"')
      expect(result).toBe('<a href="#">Link</a>')
    })

    it('should prevent img.body clobbering', () => {
      // This would make document.body point to the img element
      const html = '<img src="/logo.png" alt="Logo" name="body">'
      const result = sanitize(html, { preventDOMClobbering: true })
      expect(result).not.toContain('name="body"')
      expect(result).toBe('<img src="/logo.png" alt="Logo">')
    })

    it('should prevent multiple clobbering attempts', () => {
      const html = `
        <div id="createElement">Div</div>
        <a href="#" name="getElementById">Link</a>
        <img src="/img.jpg" alt="Image" name="body">
      `
      const result = sanitize(html, { preventDOMClobbering: true, allowIdAttribute: true })
      expect(result).not.toContain('id="createElement"')
      expect(result).not.toContain('name="getElementById"')
      expect(result).not.toContain('name="body"')
    })
  })
})
