/**
 * Event Handler XSS Vector Tests
 *
 * Tests sanitization of event handler attributes (onclick, onerror, etc.).
 * These are the most common XSS vectors.
 */

import { describe, it, expect } from 'vitest'
import { sanitize } from '../../../src/core/sanitizer.js'

describe('Event Handler XSS Vectors', () => {
  describe('Mouse event handlers', () => {
    it('should remove onclick attribute', () => {
      const html = '<div onclick="alert(\'XSS\')">Click me</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Click me</div>')
    })

    it('should remove ondblclick attribute', () => {
      const html = '<div ondblclick="alert(\'XSS\')">Double click</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Double click</div>')
    })

    it('should remove onmouseover attribute', () => {
      const html = '<div onmouseover="alert(\'XSS\')">Hover me</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Hover me</div>')
    })

    it('should remove onmouseout attribute', () => {
      const html = '<div onmouseout="alert(\'XSS\')">Move away</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Move away</div>')
    })

    it('should remove onmousedown attribute', () => {
      const html = '<div onmousedown="alert(\'XSS\')">Press me</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Press me</div>')
    })

    it('should remove onmouseup attribute', () => {
      const html = '<div onmouseup="alert(\'XSS\')">Release me</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Release me</div>')
    })

    it('should remove onmousemove attribute', () => {
      const html = '<div onmousemove="alert(\'XSS\')">Move over me</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Move over me</div>')
    })

    it('should remove oncontextmenu attribute', () => {
      const html = '<div oncontextmenu="alert(\'XSS\')">Right click</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Right click</div>')
    })
  })

  describe('Image onerror injection (very common)', () => {
    it('should remove onerror from img tag', () => {
      const html = '<img src="invalid.jpg" onerror="alert(\'XSS\')">'
      const result = sanitize(html)
      expect(result).toBe('<img src="invalid.jpg">')
    })

    it('should remove onerror with data URI', () => {
      const html = '<img src=x onerror="alert(\'XSS\')">'
      const result = sanitize(html)
      expect(result).toBe('<img src="x">')
    })

    it('should handle onerror with encoded characters', () => {
      const html = '<img src=x onerror="&#97;lert(&#39;XSS&#39;)">'
      const result = sanitize(html)
      expect(result).toBe('<img src="x">')
    })
  })

  describe('onload event handler', () => {
    it('should remove onload from body tag', () => {
      const html = '<body onload="alert(\'XSS\')">Content</body>'
      const result = sanitize(html)
      // body tag is not in allowed tags
      expect(result).toBe('Content')
    })

    it('should remove onload from img tag', () => {
      const html = '<img src="valid.jpg" onload="alert(\'XSS\')">'
      const result = sanitize(html)
      expect(result).toBe('<img src="valid.jpg">')
    })

    it('should remove onload from iframe', () => {
      const html = '<iframe onload="alert(\'XSS\')"></iframe>'
      const result = sanitize(html)
      expect(result).toBe('')
    })
  })

  describe('Keyboard event handlers', () => {
    it('should remove onkeydown attribute', () => {
      const html = '<input onkeydown="alert(\'XSS\')">'
      const result = sanitize(html)
      // input tag is not in allowed tags
      expect(result).toBe('')
    })

    it('should remove onkeyup attribute', () => {
      const html = '<input onkeyup="alert(\'XSS\')">'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove onkeypress attribute', () => {
      const html = '<input onkeypress="alert(\'XSS\')">'
      const result = sanitize(html)
      expect(result).toBe('')
    })
  })

  describe('Form event handlers', () => {
    it('should remove onsubmit from form', () => {
      const html = '<form onsubmit="alert(\'XSS\')"><button>Submit</button></form>'
      const result = sanitize(html)
      // form and button are not in allowed tags
      expect(result).toBe('')
    })

    it('should remove onchange attribute', () => {
      const html = '<input onchange="alert(\'XSS\')">'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove oninput attribute', () => {
      const html = '<input oninput="alert(\'XSS\')">'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove onfocus attribute', () => {
      const html = '<input onfocus="alert(\'XSS\')">'
      const result = sanitize(html)
      expect(result).toBe('')
    })

    it('should remove onblur attribute', () => {
      const html = '<input onblur="alert(\'XSS\')">'
      const result = sanitize(html)
      expect(result).toBe('')
    })
  })

  describe('Event handler case variations', () => {
    it('should remove ONCLICK (uppercase)', () => {
      const html = '<div ONCLICK="alert(\'XSS\')">Click</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Click</div>')
    })

    it('should remove OnClick (mixed case)', () => {
      const html = '<div OnClick="alert(\'XSS\')">Click</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Click</div>')
    })

    it('should remove onCLICK (mixed case)', () => {
      const html = '<div onCLICK="alert(\'XSS\')">Click</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Click</div>')
    })
  })

  describe('Multiple event handlers on same element', () => {
    it('should remove all event handlers from one element', () => {
      const html = '<div onclick="alert(1)" onmouseover="alert(2)" ondblclick="alert(3)">Text</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Text</div>')
    })

    it('should keep safe attributes while removing event handlers', () => {
      const html = '<a href="https://example.com" onclick="alert(\'XSS\')" title="Link">Click</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="https://example.com" title="Link">Click</a>')
    })
  })

  describe('Event handler with various JavaScript payloads', () => {
    it('should remove onclick with function call', () => {
      const html = '<div onclick="doSomethingEvil()">Click</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Click</div>')
    })

    it('should remove onclick with inline script', () => {
      const html = '<div onclick="var x=1;alert(x)">Click</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Click</div>')
    })

    it('should remove onclick with encoded payload', () => {
      const html = '<div onclick="&#97;&#108;&#101;&#114;&#116;&#40;&#39;XSS&#39;&#41;">Click</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Click</div>')
    })
  })

  describe('Less common event handlers', () => {
    it('should remove onanimationstart', () => {
      const html = '<div onanimationstart="alert(\'XSS\')">Animate</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Animate</div>')
    })

    it('should remove ontransitionend', () => {
      const html = '<div ontransitionend="alert(\'XSS\')">Transition</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Transition</div>')
    })

    it('should remove onwheel', () => {
      const html = '<div onwheel="alert(\'XSS\')">Scroll</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Scroll</div>')
    })

    it('should remove oncopy', () => {
      const html = '<div oncopy="alert(\'XSS\')">Copy me</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Copy me</div>')
    })

    it('should remove oncut', () => {
      const html = '<div oncut="alert(\'XSS\')">Cut me</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Cut me</div>')
    })

    it('should remove onpaste', () => {
      const html = '<div onpaste="alert(\'XSS\')">Paste here</div>'
      const result = sanitize(html)
      expect(result).toBe('<div>Paste here</div>')
    })
  })

  describe('Event handlers on different HTML elements', () => {
    it('should remove onclick from anchor tag', () => {
      const html = '<a href="#" onclick="alert(\'XSS\')">Link</a>'
      const result = sanitize(html)
      expect(result).toBe('<a href="#">Link</a>')
    })

    it('should remove onclick from paragraph', () => {
      const html = '<p onclick="alert(\'XSS\')">Text</p>'
      const result = sanitize(html)
      expect(result).toBe('<p>Text</p>')
    })

    it('should remove onclick from span', () => {
      const html = '<span onclick="alert(\'XSS\')">Text</span>'
      const result = sanitize(html)
      expect(result).toBe('<span>Text</span>')
    })

    it('should remove onclick from table cell', () => {
      const html = '<table><tr><td onclick="alert(\'XSS\')">Cell</td></tr></table>'
      const result = sanitize(html)
      expect(result).toBe('<table><tbody><tr><td>Cell</td></tr></tbody></table>')
    })
  })
})
