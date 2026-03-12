/**
 * Basic XSS Vectors and Edge Cases
 *
 * Tests for OWASP top XSS vectors and edge cases.
 * Covers common patterns and sanitization behavior.
 */

import { describe, it, expect } from 'vitest'
import { sanitize, sanitizeBasic, sanitizeRelaxed, sanitizeStrict } from '../../../src/core/sanitizer.js'

describe('Basic XSS Vectors', () => {
  describe('Safe HTML should pass through', () => {
    it('should allow safe paragraph', () => {
      const html = '<p>Hello world</p>'
      const result = sanitize(html)
      expect(result).toBe('<p>Hello world</p>')
    })

    it('should allow safe text formatting', () => {
      const html = '<p>Hello <strong>bold</strong> and <em>italic</em> text</p>'
      const result = sanitize(html)
      expect(result).toBe('<p>Hello <strong>bold</strong> and <em>italic</em> text</p>')
    })

    it('should allow safe links', () => {
      const html = '<a href="https://example.com" title="Example">Click here</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="https://example.com" title="Example">Click here</a>')
    })

    it('should allow safe images', () => {
      const html = '<img src="https://example.com/image.jpg" alt="Description">'
      const result = sanitize(html)
      expect(result).toBe('<img src="https://example.com/image.jpg" alt="Description">')
    })

    it('should allow safe lists', () => {
      const html = '<ul><li>Item 1</li><li>Item 2</li></ul>'
      const result = sanitize(html)
      expect(result).toBe('<ul><li>Item 1</li><li>Item 2</li></ul>')
    })

    it('should allow safe tables', () => {
      const html = '<table><tr><th>Header</th></tr><tr><td>Data</td></tr></table>'
      const result = sanitize(html)
      expect(result).toBe('<table><tbody><tr><th>Header</th></tr><tr><td>Data</td></tr></tbody></table>')
    })
  })

  describe('Mixed safe and unsafe content', () => {
    it('should keep safe content and remove unsafe script', () => {
      const html = '<p>Safe text</p><script>alert("XSS")</script><p>More safe text</p>'
      const result = sanitize(html)
      expect(result).toBe('<p>Safe text</p><p>More safe text</p>')
    })

    it('should keep safe attributes and remove unsafe onclick', () => {
      const html = '<div class="container" onclick="alert(1)" id="main">Content</div>'
      const result = sanitize(html)
      // class and id are not allowed by default
      expect(result).toBe('<div>Content</div>')
    })

    it('should keep safe protocol and remove dangerous protocol', () => {
      const html = `
        <a href="https://safe.com">Safe</a>
        <a href="javascript:alert(1)">Unsafe</a>
      `
      const result = sanitize(html)
      expect(result).toContain('https://safe.com')
      expect(result).not.toContain('javascript:')
    })
  })

  describe('Empty and whitespace content', () => {
    it('should handle empty string', () => {
      const html = ''
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should handle whitespace only', () => {
      const html = '   \n   \t   '
      const result = sanitize(html)
      // Browser DOMParser normalizes whitespace-only content to empty string
      expect(result).toBe('')
    })

    it('should handle empty tags', () => {
      const html = '<p></p>'
      const result = sanitize(html)
      expect(result).toBe('<p></p>')
    })

    it('should preserve text content without tags', () => {
      const html = 'Plain text without any tags'
      const result = sanitize(html)
      expect(result).toBe('Plain text without any tags')
    })
  })

  describe('Nested HTML structures', () => {
    it('should handle deeply nested safe HTML', () => {
      const html = '<div><p><strong><em>Nested</em></strong></p></div>'
      const result = sanitize(html)
      expect(result).toBe('<div><p><strong><em>Nested</em></strong></p></div>')
    })

    it('should handle nested unsafe HTML', () => {
      const html = '<div><p><script>alert(1)</script></p></div>'
      const result = sanitize(html)
      expect(result).toBe('<div><p></p></div>')
    })

    it('should handle mixed nesting', () => {
      const html = '<div><p>Safe</p><script>alert(1)</script><p>Also safe</p></div>'
      const result = sanitize(html)
      expect(result).toBe('<div><p>Safe</p><p>Also safe</p></div>')
    })
  })

  describe('Special characters and encoding', () => {
    it('should preserve HTML entities', () => {
      const html = '<p>&lt;p&gt;Test&lt;/p&gt;</p>'
      const result = sanitize(html)
      expect(result).toBe('<p>&lt;p&gt;Test&lt;/p&gt;</p>')
    })

    it('should preserve Unicode characters', () => {
      const html = '<p>Hello 世界 🌍</p>'
      const result = sanitize(html)
      expect(result).toBe('<p>Hello 世界 🌍</p>')
    })

    it('should handle quotes in attributes', () => {
      const html = '<a href="https://example.com?q=test&amp;lang=en" title="It\'s a link">Click</a>'
      const result = sanitize(html)
      expect(result).toContain('href=')
      expect(result).toContain('title=')
    })
  })

  describe('HTML comments', () => {
    it('should remove HTML comments', () => {
      const html = '<p>Text</p><!-- Comment --><p>More text</p>'
      const result = sanitize(html)
      expect(result).not.toContain('<!--')
      expect(result).toBe('<p>Text</p><p>More text</p>')
    })

    it('should remove comments with script inside', () => {
      const html = '<!-- <script>alert(1)</script> --><p>Text</p>'
      const result = sanitize(html)
      expect(result).not.toContain('script')
      expect(result).toBe('<p>Text</p>')
    })
  })

  describe('Self-closing tags', () => {
    it('should handle br tag', () => {
      const html = '<p>Line 1<br>Line 2</p>'
      const result = sanitize(html)
      expect(result).toBe('<p>Line 1<br>Line 2</p>')
    })

    it('should handle hr tag', () => {
      const html = '<p>Section 1</p><hr><p>Section 2</p>'
      const result = sanitize(html)
      expect(result).toBe('<p>Section 1</p><hr><p>Section 2</p>')
    })

    it('should handle img tag (self-closing)', () => {
      const html = '<img src="/image.jpg" alt="Test">'
      const result = sanitize(html)
      expect(result).toBe('<img src="/image.jpg" alt="Test">')
    })
  })
})

describe('Schema-based sanitization', () => {
  describe('BASIC schema', () => {
    it('should allow minimal HTML', () => {
      const html = '<p><strong>Bold</strong> text</p>'
      const result = sanitizeBasic(html)
      expect(result).toBe('<p><strong>Bold</strong> text</p>')
    })

    it('should remove images (not in BASIC schema)', () => {
      const html = '<p>Text</p><img src="image.jpg"><p>More</p>'
      const result = sanitizeBasic(html)
      expect(result).toBe('<p>Text</p><p>More</p>')
    })

    it('should allow links', () => {
      const html = '<a href="https://example.com">Link</a>'
      const result = sanitizeBasic(html)
      expect(result).toBe('<a href="https://example.com">Link</a>')
    })
  })

  describe('RELAXED schema', () => {
    it('should allow rich HTML including images', () => {
      const html = '<p>Text</p><img src="https://example.com/image.jpg" alt="Image">'
      const result = sanitizeRelaxed(html)
      expect(result).toBe('<p>Text</p><img src="https://example.com/image.jpg" alt="Image">')
    })

    it('should allow tables', () => {
      const html = '<table><tr><td>Cell</td></tr></table>'
      const result = sanitizeRelaxed(html)
      expect(result).toContain('<table>')
      expect(result).toContain('<td>Cell</td>')
    })

    it('should still remove scripts', () => {
      const html = '<p>Safe</p><script>alert(1)</script>'
      const result = sanitizeRelaxed(html)
      expect(result).toBe('<p>Safe</p>')
    })
  })

  describe('STRICT schema', () => {
    it('should strip all HTML tags', () => {
      const html = '<p>Just <strong>text</strong> content</p>'
      const result = sanitizeStrict(html)
      expect(result).toBe('Just text content')
    })

    it('should remove scripts and keep text', () => {
      const html = '<p>Safe</p><script>alert(1)</script><p>Text</p>'
      const result = sanitizeStrict(html)
      expect(result).toBe('SafeText')
    })

    it('should handle plain text', () => {
      const html = 'Just plain text'
      const result = sanitizeStrict(html)
      expect(result).toBe('Just plain text')
    })
  })
})

describe('Edge cases and error handling', () => {
  describe('Malformed HTML', () => {
    it('should handle unclosed tags', () => {
      const html = '<p>Unclosed paragraph'
      const result = sanitize(html)
      expect(result).toBe('<p>Unclosed paragraph</p>')
    })

    it('should handle mismatched tags', () => {
      const html = '<p>Start</strong>End</p>'
      const result = sanitize(html)
      // Browser auto-corrects to valid HTML
      expect(result).toContain('Start')
      expect(result).toContain('End')
    })

    it('should handle nested tags in wrong order', () => {
      const html = '<p><strong><em>Text</p></em></strong>'
      const result = sanitize(html)
      // Browser auto-corrects structure
      expect(result).toContain('Text')
    })
  })

  describe('Very long content', () => {
    it('should handle long text content', () => {
      const longText = 'A'.repeat(10000)
      const html = `<p>${longText}</p>`
      const result = sanitize(html)
      expect(result).toContain(longText)
    })

    it('should handle many nested elements', () => {
      let html = 'Text'
      for (let i = 0; i < 100; i++) {
        html = `<div>${html}</div>`
      }
      const result = sanitize(html)
      expect(result).toContain('Text')
    })
  })

  describe('Special input types', () => {
    it('should handle null input gracefully', () => {
      const result = sanitize(null as unknown as string)
      expect(result).toBe('')
    })

    it('should handle undefined input gracefully', () => {
      const result = sanitize(undefined as unknown as string)
      expect(result).toBe('')
    })

    it('should handle number input gracefully', () => {
      const result = sanitize(123 as unknown as string)
      expect(result).toBe('')
    })
  })
})
