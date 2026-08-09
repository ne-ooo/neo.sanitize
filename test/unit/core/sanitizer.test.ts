import { describe, expect, it } from 'vitest'
import { sanitize } from '../../../src/core/sanitizer.js'

describe('wrapper removal', () => {
  it('unwraps unknown elements after sanitizing their descendants', () => {
    const result = sanitize(
      '<section><p onclick="alert(1)"><strong>Safe</strong><script>bad()</script></p></section>'
    )

    expect(result).toBe('<p><strong>Safe</strong></p>')
  })

  it('removes an unknown subtree when text retention is disabled', () => {
    const result = sanitize('<section><p>Remove</p></section><p>Keep</p>', {
      keepTextContent: false,
    })

    expect(result).toBe('<p>Keep</p>')
  })

  it('strips allowed wrappers and keeps sanitized descendants', () => {
    const result = sanitize(
      '<p><strong>Bold</strong><a href="javascript:alert(1)"> link</a><script>bad()</script></p>',
      { stripTags: true }
    )

    expect(result).toBe('Bold link')
  })

  it('always removes dangerous subtrees when stripTags is enabled', () => {
    const result = sanitize('<style>body { color: red }</style><script>alert(1)</script>Safe', {
      stripTags: true,
    })

    expect(result).toBe('Safe')
  })
})
