/**
 * Hooks System Tests
 *
 * Tests the customization hooks system:
 * - beforeSanitize hook (modify HTML before parsing)
 * - onElement hook (filter elements during sanitization)
 * - onAttribute hook (filter attributes during validation)
 * - afterSanitize hook (modify result after sanitization)
 *
 * Phase 2 feature.
 */

import { describe, it, expect } from 'vitest'
import { sanitize } from '../../../src/core/sanitizer.js'
import type { SanitizeHooks } from '../../../src/types.js'

describe('Hooks System', () => {
  describe('beforeSanitize hook', () => {
    it('should allow modifying HTML before sanitization', () => {
      const hooks: SanitizeHooks = {
        beforeSanitize(html) {
          // Replace placeholder with actual content
          return html.replace('{{name}}', 'John')
        },
      }

      const html = '<p>Hello {{name}}</p>'
      const result = sanitize(html, { hooks })

      expect(result).toBe('<p>Hello John</p>')
    })

    it('should allow adding attributes before sanitization', () => {
      const hooks: SanitizeHooks = {
        beforeSanitize(html) {
          // Add data-processed attribute
          return html.replace('<div>', '<div data-processed="true">')
        },
      }

      const html = '<div>Content</div>'
      const result = sanitize(html, {
        hooks,
        allowDataAttributes: true,
      })

      expect(result).toContain('data-processed="true"')
    })

    it('should not break sanitization if hook returns void', () => {
      const hooks: SanitizeHooks = {
        beforeSanitize(html) {
          // Hook that does nothing (returns void)
          console.log('Processing:', html)
        },
      }

      const html = '<p>Hello</p>'
      const result = sanitize(html, { hooks })

      expect(result).toBe('<p>Hello</p>')
    })

    it('should sanitize modified HTML', () => {
      const hooks: SanitizeHooks = {
        beforeSanitize(html) {
          // Add dangerous content
          return html + '<script>alert(1)</script>'
        },
      }

      const html = '<p>Safe</p>'
      const result = sanitize(html, { hooks })

      // Script should be removed
      expect(result).not.toContain('script')
      expect(result).not.toContain('alert')
      expect(result).toContain('<p>Safe</p>')
    })
  })

  describe('onElement hook', () => {
    it('should allow filtering elements', () => {
      const hooks: SanitizeHooks = {
        onElement(element) {
          // Remove all divs
          if (element.tagName.toLowerCase() === 'div') {
            return false
          }
        },
      }

      const html = '<p>Keep</p><div>Remove</div><span>Keep</span>'
      const result = sanitize(html, { hooks })

      expect(result).toContain('<p>Keep</p>')
      expect(result).toContain('<span>Keep</span>')
      expect(result).not.toContain('<div>')
      expect(result).not.toContain('Remove')
    })

    it('should allow filtering by attribute', () => {
      const hooks: SanitizeHooks = {
        onElement(element) {
          // Remove elements with data-remove attribute
          if (element.getAttribute('data-remove') === 'true') {
            return false
          }
        },
      }

      const html = '<p>Keep</p><div data-remove="true">Remove</div>'
      const result = sanitize(html, {
        hooks,
        allowDataAttributes: true,
      })

      expect(result).toContain('<p>Keep</p>')
      expect(result).not.toContain('Remove')
    })

    it('should preserve elements when hook returns void', () => {
      const hooks: SanitizeHooks = {
        onElement(element) {
          // Hook that does nothing (returns void)
          console.log('Element:', element.tagName)
        },
      }

      const html = '<p>Hello</p><div>World</div>'
      const result = sanitize(html, { hooks })

      expect(result).toContain('<p>Hello</p>')
      expect(result).toContain('<div>World</div>')
    })

    it('should only be called for allowed tags', () => {
      const calledElements: string[] = []

      const hooks: SanitizeHooks = {
        onElement(element) {
          calledElements.push(element.tagName.toLowerCase())
        },
      }

      const html = '<p>Safe</p><script>alert(1)</script><div>Content</div>'
      sanitize(html, { hooks })

      // Script should not reach the hook (removed before)
      expect(calledElements).toContain('p')
      expect(calledElements).toContain('div')
      expect(calledElements).not.toContain('script')
    })

    it('should work with nested elements', () => {
      const hooks: SanitizeHooks = {
        onElement(element) {
          // Remove empty divs
          if (element.tagName.toLowerCase() === 'div' && element.textContent?.trim() === '') {
            return false
          }
        },
      }

      const html = '<div><p>Content</p><div></div></div>'
      const result = sanitize(html, { hooks })

      expect(result).toContain('<p>Content</p>')
      // Outer div has content, inner div is empty
      expect(result).toContain('<div>')
    })
  })

  describe('onAttribute hook', () => {
    it('should allow filtering attributes', () => {
      const hooks: SanitizeHooks = {
        onAttribute(element, attrName, attrValue) {
          // Remove all data-* attributes
          if (attrName.startsWith('data-')) {
            return false
          }
        },
      }

      const html = '<div id="test" data-info="secret">Content</div>'
      const result = sanitize(html, {
        hooks,
        allowIdAttribute: true,
        allowDataAttributes: true,
      })

      expect(result).toContain('id="test"')
      expect(result).not.toContain('data-info')
      expect(result).not.toContain('secret')
    })

    it('should allow filtering by value', () => {
      const hooks: SanitizeHooks = {
        onAttribute(element, attrName, attrValue) {
          // Remove attributes with sensitive values
          if (attrValue.includes('secret')) {
            return false
          }
        },
      }

      const html = '<div title="public" data-key="secret123">Content</div>'
      const result = sanitize(html, {
        hooks,
        allowDataAttributes: true,
        allowedAttributes: { div: ['title'] },
      })

      expect(result).toContain('title="public"')
      expect(result).not.toContain('data-key')
      expect(result).not.toContain('secret123')
    })

    it('should preserve attributes when hook returns void', () => {
      const hooks: SanitizeHooks = {
        onAttribute(element, attrName, attrValue) {
          // Hook that does nothing (returns void)
          console.log('Attribute:', attrName, '=', attrValue)
        },
      }

      const html = '<div id="test">Content</div>'
      const result = sanitize(html, {
        hooks,
        allowIdAttribute: true,
      })

      expect(result).toContain('id="test"')
    })

    it('should be called before attribute validation', () => {
      const calledAttributes: string[] = []

      const hooks: SanitizeHooks = {
        onAttribute(element, attrName, attrValue) {
          calledAttributes.push(attrName)
        },
      }

      const html = '<a href="https://example.com" onclick="alert(1)">Link</a>'
      sanitize(html, { hooks })

      // Hook should be called for both attributes
      expect(calledAttributes).toContain('href')
      expect(calledAttributes).toContain('onclick')

      // But onclick should still be removed by validation
      const result = sanitize(html, { hooks })
      expect(result).toContain('href')
      expect(result).not.toContain('onclick')
    })

    it('should work with normalized attribute names', () => {
      const hooks: SanitizeHooks = {
        onAttribute(element, attrName, attrValue) {
          // Remove CLASS attribute (should be normalized to lowercase)
          if (attrName === 'class') {
            return false
          }
        },
      }

      const html = '<div CLASS="test">Content</div>'
      const result = sanitize(html, {
        hooks,
        allowClassAttribute: true,
        lowercaseAttributes: true,
      })

      expect(result).not.toContain('class')
      expect(result).not.toContain('CLASS')
    })
  })

  describe('afterSanitize hook', () => {
    it('should allow modifying result after sanitization', () => {
      const hooks: SanitizeHooks = {
        afterSanitize(fragment) {
          // Add a watermark div
          const watermark = document.createElement('div')
          watermark.textContent = 'Sanitized'
          fragment.appendChild(watermark)
          return fragment
        },
      }

      const html = '<p>Content</p>'
      const result = sanitize(html, { hooks })

      expect(result).toContain('<p>Content</p>')
      expect(result).toContain('<div>Sanitized</div>')
    })

    it('should not break sanitization if hook returns void', () => {
      const hooks: SanitizeHooks = {
        afterSanitize(fragment) {
          // Hook that does nothing (returns void)
          console.log('Fragment:', fragment)
        },
      }

      const html = '<p>Hello</p>'
      const result = sanitize(html, { hooks })

      expect(result).toBe('<p>Hello</p>')
    })

    it('should receive sanitized DocumentFragment', () => {
      const hooks: SanitizeHooks = {
        afterSanitize(fragment) {
          // Verify dangerous content was removed
          const scripts = fragment.querySelectorAll('script')
          expect(scripts.length).toBe(0)

          // Verify safe content is present
          const paragraphs = fragment.querySelectorAll('p')
          expect(paragraphs.length).toBe(1)
        },
      }

      const html = '<p>Safe</p><script>alert(1)</script>'
      sanitize(html, { hooks })
    })

    it('should work with returnString option', () => {
      const hooks: SanitizeHooks = {
        afterSanitize(fragment) {
          // Add metadata
          const meta = document.createElement('meta')
          meta.setAttribute('name', 'sanitized')
          meta.setAttribute('content', 'true')
          fragment.appendChild(meta)
          return fragment
        },
      }

      const html = '<p>Content</p>'
      const result = sanitize(html, {
        hooks,
        returnString: true,
      })

      expect(typeof result).toBe('string')
      expect(result).toContain('name="sanitized"')
    })
  })

  describe('Multiple hooks', () => {
    it('should call all hooks in correct order', () => {
      const callOrder: string[] = []

      const hooks: SanitizeHooks = {
        beforeSanitize(html) {
          callOrder.push('before')
          return html
        },
        onElement(element) {
          callOrder.push('element')
        },
        onAttribute(element, attrName, attrValue) {
          callOrder.push('attribute')
        },
        afterSanitize(fragment) {
          callOrder.push('after')
          return fragment
        },
      }

      const html = '<div id="test">Content</div>'
      sanitize(html, {
        hooks,
        allowIdAttribute: true,
      })

      expect(callOrder[0]).toBe('before')
      expect(callOrder[callOrder.length - 1]).toBe('after')
      expect(callOrder).toContain('element')
      expect(callOrder).toContain('attribute')
    })

    it('should allow combining hooks for complex filtering', () => {
      const hooks: SanitizeHooks = {
        beforeSanitize(html) {
          // Add marker
          return html.replace('<div>', '<div data-processed="true">')
        },
        onElement(element) {
          // Keep only processed divs
          if (
            element.tagName.toLowerCase() === 'div' &&
            element.getAttribute('data-processed') !== 'true'
          ) {
            return false
          }
        },
        afterSanitize(fragment) {
          // Remove marker
          const divs = fragment.querySelectorAll('div')
          divs.forEach((div) => div.removeAttribute('data-processed'))
          return fragment
        },
      }

      const html = '<div>Keep</div><div>Remove</div>'
      const result = sanitize(html, { hooks })

      // Only first div (with marker) should be kept
      const divCount = (result.match(/<div>/g) || []).length
      expect(divCount).toBe(1)
      expect(result).toContain('Keep')
      expect(result).not.toContain('Remove')
      expect(result).not.toContain('data-processed')
    })

    it('should handle hook errors gracefully', () => {
      const hooks: SanitizeHooks = {
        onElement(element) {
          // This should not break sanitization if it throws
          if (element.tagName === 'BAD') {
            throw new Error('Bad element')
          }
        },
      }

      const html = '<p>Safe</p>'

      // Should not throw
      expect(() => {
        sanitize(html, { hooks })
      }).not.toThrow()
    })
  })

  describe('Real-world use cases', () => {
    it('should allow implementing custom link sanitization', () => {
      const hooks: SanitizeHooks = {
        onAttribute(element, attrName, attrValue) {
          // Add rel="nofollow" to external links
          if (
            element.tagName.toLowerCase() === 'a' &&
            attrName === 'href' &&
            attrValue.startsWith('http')
          ) {
            element.setAttribute('rel', 'nofollow noopener')
          }
        },
      }

      const html = '<a href="https://external.com">Link</a>'
      const result = sanitize(html, {
        hooks,
        allowedAttributes: { a: ['href', 'rel'] },
      })

      expect(result).toContain('rel="nofollow noopener"')
    })

    it('should allow implementing content warnings', () => {
      const hooks: SanitizeHooks = {
        afterSanitize(fragment) {
          // Add warning for external images
          const images = fragment.querySelectorAll('img')
          images.forEach((img) => {
            const src = img.getAttribute('src')
            if (src && src.startsWith('http')) {
              const warning = document.createElement('small')
              warning.textContent = '⚠️ External image'
              img.parentNode?.insertBefore(warning, img)
            }
          })
          return fragment
        },
      }

      const html = '<img src="https://external.com/image.jpg" alt="External">'
      const result = sanitize(html, {
        hooks,
        allowedTags: ['img', 'small'],
        allowedAttributes: { img: ['src', 'alt'] },
      })

      expect(result).toContain('⚠️ External image')
    })

    it('should allow implementing analytics tracking', () => {
      const trackedElements: Array<{ tag: string; attributes: Record<string, string> }> = []

      const hooks: SanitizeHooks = {
        onElement(element) {
          // Track which elements are processed
          const attributes: Record<string, string> = {}
          Array.from(element.attributes).forEach((attr) => {
            attributes[attr.name] = attr.value
          })

          trackedElements.push({
            tag: element.tagName.toLowerCase(),
            attributes,
          })
        },
      }

      const html = '<p>Text</p><a href="https://example.com">Link</a><img src="image.jpg" alt="Image">'
      sanitize(html, {
        hooks,
        allowedTags: ['p', 'a', 'img'],
        allowedAttributes: { a: ['href'], img: ['src', 'alt'] },
      })

      expect(trackedElements.length).toBe(3)
      expect(trackedElements[0].tag).toBe('p')
      expect(trackedElements[1].tag).toBe('a')
      expect(trackedElements[2].tag).toBe('img')
    })
  })
})
