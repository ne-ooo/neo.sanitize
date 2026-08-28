import { describe, expect, it } from 'vitest'
import { sanitize, serializeHTML } from '../../../src/index.js'

describe('parser-context security boundaries', () => {
  it('removes declarative shadow DOM and its complete template subtree', () => {
    const dirty =
      '<div><template shadowrootmode="open"><img src=x onerror=alert(1)>' +
      '<a href="javascript:alert(2)">x</a></template><p>safe</p></div>'

    expect(sanitize(dirty)).toBe('<div><p>safe</p></div>')
  })

  it('removes nested template content', () => {
    const dirty =
      '<template><template><img src=x onerror=alert(1)></template></template>' +
      '<p>safe</p>'

    expect(sanitize(dirty)).toBe('<p>safe</p>')
  })

  it('removes iframe srcdoc payloads as complete subtrees', () => {
    const dirty =
      '<iframe srcdoc="<script>alert(1)</script>"><p>fallback</p></iframe>' +
      '<p>safe</p>'

    expect(sanitize(dirty)).toBe('<p>safe</p>')
  })

  it('removes selectedcontent parsing contexts', () => {
    const dirty =
      '<select><option><img src=x onerror=alert(1)></option>' +
      '<selectedcontent></selectedcontent></select><p>safe</p>'

    expect(sanitize(dirty)).toBe('<p>safe</p>')
  })

  it('rejects custom elements even when a custom allowlist contains them', () => {
    const dirty = '<user-card data-command="run"><p>inside</p></user-card><p>safe</p>'
    const result = sanitize(dirty, {
      allowedTags: ['user-card', 'p'],
      allowedAttributes: { 'user-card': ['data-command'] },
      allowDataAttributes: true,
    })

    expect(result).toBe('<p>safe</p>')
  })

  it('rejects customized built-ins by default', () => {
    const dirty = '<p is="dangerous-paragraph">safe text</p>'
    const result = sanitize(dirty, {
      allowedTags: ['p'],
      allowedAttributes: { p: ['is'] },
      allowAllAttributes: ['p'],
    })

    expect(result).toBe('')
  })

  it('permits explicitly listed custom elements only after an unsafe opt-in', () => {
    const dirty =
      '<user-card data-label="safe" onclick="alert(1)"><p>inside</p></user-card>'
    const result = sanitize(dirty, {
      allowedTags: ['user-card', 'p'],
      allowedAttributes: { 'user-card': ['data-label'] },
      allowCustomElements: true,
    })

    expect(result).toBe('<user-card data-label="safe"><p>inside</p></user-card>')
  })

  it('ignores inherited configuration that attempts to enable custom elements', () => {
    const options = Object.create({
      allowedTags: ['user-card'],
      allowedAttributes: { 'user-card': ['onclick'] },
      allowAllAttributes: ['user-card'],
      allowCustomElements: true,
    })

    expect(sanitize('<user-card onclick="alert(1)">x</user-card>', options)).toBe('')
  })

  it('does not invoke configuration accessors', () => {
    const options: Record<string, unknown> = {}
    Object.defineProperties(options, {
      allowedTags: {
        enumerable: true,
        get: () => {
          throw new Error('configuration getter ran')
        },
      },
      allowCustomElements: {
        enumerable: true,
        get: () => {
          throw new Error('configuration getter ran')
        },
      },
      hooks: {
        enumerable: true,
        get: () => {
          throw new Error('configuration getter ran')
        },
      },
    })

    expect(sanitize('<user-card>x</user-card><p>safe</p>', options)).toBe(
      '<p>safe</p>'
    )
  })

  it('remains stable after repeated parsing and sanitization', () => {
    const dirty =
      '<math><mtext><table><mglyph><style><!--</style>' +
      '<img src=x onerror=alert(1)><p>safe</p>'

    const once = sanitize(dirty, { detectMXSS: true }) as string
    const twice = sanitize(once, { detectMXSS: true }) as string
    const threeTimes = sanitize(twice, { detectMXSS: true }) as string

    expect(once).toBe(twice)
    expect(twice).toBe(threeTimes)
    expect(once).not.toMatch(/<math|<svg|<script|\son[a-z]+\s*=|javascript:/i)
  })

  it('does not let form named properties skip following siblings', () => {
    const dirty =
      '<form><input name="nextSibling"></form>' +
      '<img src=x onerror="window.__xss=1">' +
      '<script>window.__xss=2</script>'

    expect(sanitize(dirty)).toBe('<img src="x">')

    const fragment = sanitize(dirty, { returnString: false }) as DocumentFragment
    expect(serializeHTML(fragment)).toBe('<img src="x">')
  })

  it('fails closed when form controls shadow traversal properties', () => {
    for (const property of [
      'childNodes',
      'firstChild',
      'localName',
      'nodeType',
      'ownerDocument',
      'parentNode',
    ]) {
      const dirty =
        `<form><input name="${property}"></form>` +
        '<img src=x onerror=alert(1)><script>alert(2)</script>'

      expect(sanitize(dirty), property).toBe('<img src="x">')
    }
  })
})
