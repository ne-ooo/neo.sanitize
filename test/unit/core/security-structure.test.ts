// @vitest-environment node

import { JSDOM } from 'jsdom'
import { describe, expect, it } from 'vitest'
import type { DOMRuntime } from '../../../src/types.js'
import { getHTMLSecurityStructure } from '../../differential/security-structure.js'

const window = new JSDOM('').window
const runtime: DOMRuntime = {
  document: window.document,
  DOMParser: window.DOMParser,
}

describe('differential security structure', () => {
  it('distinguishes trees whose parent tag names are identical', () => {
    const nested = '<div><div><span></span></div></div>'
    const siblings = '<div><div></div><span></span></div>'

    expect(getHTMLSecurityStructure(nested, runtime, 'body')).not.toBe(
      getHTMLSecurityStructure(siblings, runtime, 'body')
    )
  })
})
