import { describe, expect, it } from 'vitest'
import {
  HTML_INSERTION_CONTEXTS,
  compileSanitizeOptions,
  parseHTML,
  sanitize,
  serializeHTML,
} from '../../../src/index.js'

describe('context-aware HTML parsing', () => {
  it('preserves the body parser as the default', () => {
    const dirty = '<tr><td>safe<img src=x onerror=alert(1)></td></tr>'

    expect(sanitize(dirty)).toBe('safe<img src="x">')
    expect(sanitize(dirty, { insertionContext: 'body' })).toBe(
      'safe<img src="x">'
    )
  })

  it('uses body fragment parsing instead of full-document parsing', () => {
    const dirty =
      '<div id="31"><frameset onload=alert(31)>//["\'`-->]]>]</div>'

    expect(sanitize(dirty, { insertionContext: 'body' })).toBe(
      '<div>//["\'`--&gt;]]&gt;]</div>'
    )
  })

  it('uses the table fragment parser for table content', () => {
    const dirty = '<tr><td>safe<img src=x onerror=alert(1)></td></tr>'

    expect(sanitize(dirty, { insertionContext: 'table' })).toBe(
      '<tbody><tr><td>safe<img src="x"></td></tr></tbody>'
    )
  })

  it.each([
    ['tbody', '<tr><td>safe</td></tr>', '<tr><td>safe</td></tr>'],
    ['thead', '<tr><th>safe</th></tr>', '<tr><th>safe</th></tr>'],
    ['tfoot', '<tr><td>safe</td></tr>', '<tr><td>safe</td></tr>'],
    ['tr', '<td>safe</td>', '<td>safe</td>'],
    ['td', '<p>safe<script>bad()</script></p>', '<p>safe</p>'],
    ['th', '<strong>safe</strong>', '<strong>safe</strong>'],
    ['caption', '<em>safe</em>', '<em>safe</em>'],
    ['colgroup', '<col span=2><script>bad()</script>', '<col span="2">'],
  ] as const)('sanitizes the %s insertion context', (context, dirty, expected) => {
    expect(sanitize(dirty, { insertionContext: context })).toBe(expected)
  })

  it('handles select-family contexts conservatively', () => {
    const dirty =
      'safe<option>removed<img src=x onerror=alert(1)></option>' +
      '<script>alert(2)</script>'

    expect(sanitize(dirty, { insertionContext: 'select' })).toBe('safe')
    expect(sanitize('safe<img src=x onerror=alert(1)>', {
      insertionContext: 'option',
    })).toBe('safe<img src="x">')
  })

  it('returns a live-runtime fragment after contextual sanitization', () => {
    const result = sanitize('<tr><td>safe</td></tr>', {
      insertionContext: 'table',
      returnString: false,
    }) as DocumentFragment

    expect(result.ownerDocument).toBe(document)
    expect(serializeHTML(result)).toBe(
      '<tbody><tr><td>safe</td></tr></tbody>'
    )
  })

  it('stabilizes output in the selected insertion context', () => {
    const dirty =
      '<tr><td><math><mtext><table><mglyph><style><!--</style>' +
      '<img src=x onerror=alert(1)>safe</td></tr>'
    const options = { insertionContext: 'table' as const, detectMXSS: true }
    const clean = sanitize(dirty, options) as string

    expect(sanitize(clean, options)).toBe(clean)
    expect(clean).not.toMatch(/<math|<svg|<script|\son[a-z]+\s*=/i)
  })

  it.each([
    ['tr', '<td>safe</td>', 1, '<td>safe</td>'],
    ['tbody', '<tr><td>safe</td></tr>', 2, '<tr><td>safe</td></tr>'],
  ] as const)(
    'applies the actual parsed depth in the %s context',
    (insertionContext, dirty, maxDOMDepth, expected) => {
      expect(sanitize(dirty, { insertionContext, maxDOMDepth })).toBe(expected)
    }
  )

  it('supports contextual parsing through the parser API', () => {
    const fragment = parseHTML('<tr><td>safe</td></tr>', undefined, 'table')

    expect(serializeHTML(fragment)).toBe(
      '<tbody><tr><td>safe</td></tr></tbody>'
    )
  })

  it('publishes the complete supported context list', () => {
    expect(HTML_INSERTION_CONTEXTS).toContain('body')
    expect(HTML_INSERTION_CONTEXTS).toContain('table')
    expect(HTML_INSERTION_CONTEXTS).toContain('select')
    expect(HTML_INSERTION_CONTEXTS).not.toContain('script')
    expect(Object.isFrozen(HTML_INSERTION_CONTEXTS)).toBe(true)
  })

  it('rejects unsupported or raw-text contexts', () => {
    expect(() =>
      sanitize('<img src=x onerror=alert(1)>', {
        insertionContext: 'script',
      } as never)
    ).toThrow(/Unsupported insertion context/)
  })

  it('stores the selected context in compiled options', () => {
    const options = compileSanitizeOptions({ insertionContext: 'table' })

    expect(options.insertionContext).toBe('table')
    expect(sanitize('<tr><td>safe</td></tr>', options)).toContain('<tbody>')
  })

  it('ignores inherited insertion contexts', () => {
    const options = Object.create({ insertionContext: 'table' })

    expect(sanitize('<tr><td>safe</td></tr>', options)).toBe('safe')
  })
})
