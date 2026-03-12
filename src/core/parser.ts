/**
 * @lpm.dev/neo.sanitize - HTML Parser
 *
 * Universal HTML parser supporting both browser and Node.js:
 * - Browser: Uses native DOMParser (fast, mXSS-resistant)
 * - Node.js: Uses jsdom for now (Phase 2b complete, integration pending)
 */

/**
 * Check if we're in a browser environment
 *
 * @returns True if browser APIs are available
 */
export function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof document !== 'undefined' && typeof DOMParser !== 'undefined'
}

/**
 * Check if we're in a Node.js environment
 *
 * @returns True if running in Node.js
 */
export function isNode(): boolean {
  return (
    typeof process !== 'undefined' &&
    process.versions !== undefined &&
    process.versions.node !== undefined
  )
}

/**
 * Parse HTML string to DocumentFragment
 *
 * Universal parser that works in both environments:
 * - Browser: Uses native DOMParser (highly performant, mXSS-resistant)
 * - Node.js: Uses jsdom (full HTML5 compliance)
 *
 * Future: Will use @lpm.dev/neo.dom for Node.js (lighter, faster)
 *
 * @param html - HTML string to parse
 * @returns DocumentFragment containing parsed DOM tree
 *
 * @example
 * const fragment = parseHTML('<p>Hello <strong>world</strong></p>')
 * // DocumentFragment { childNodes: [<p>] }
 */
export function parseHTML(html: string): DocumentFragment {
  // Browser environment - use native DOMParser
  if (isBrowser()) {
    const parser = new DOMParser()
    const doc = parser.parseFromString(html, 'text/html')

    const fragment = document.createDocumentFragment()

    // Move all nodes from body to fragment
    while (doc.body.firstChild) {
      fragment.appendChild(doc.body.firstChild)
    }

    return fragment
  }

  // Node.js environment - use jsdom (existing implementation)
  // NOTE: jsdom is a dev dependency, used for testing
  // Future: Replace with @lpm.dev/neo.dom for production use
  if (typeof DOMParser === 'undefined') {
    throw new Error(
      '@lpm.dev/neo.sanitize: DOMParser not available. ' +
        'Browser environment required or use jsdom in Node.js for testing.'
    )
  }

  // Fallback to global DOMParser (provided by test environment)
  const parser = new DOMParser()
  const doc = parser.parseFromString(html, 'text/html')

  const fragment = (typeof document !== 'undefined' ? document : (doc as any).defaultView.document).createDocumentFragment()

  while (doc.body.firstChild) {
    fragment.appendChild(doc.body.firstChild)
  }

  return fragment
}

/**
 * Serialize DocumentFragment to HTML string
 *
 * Converts DOM tree back to HTML string.
 *
 * @param fragment - DocumentFragment to serialize
 * @returns HTML string
 *
 * @example
 * const fragment = document.createDocumentFragment()
 * const p = document.createElement('p')
 * p.textContent = 'Hello world'
 * fragment.appendChild(p)
 *
 * const html = serializeHTML(fragment)
 * // '<p>Hello world</p>'
 */
export function serializeHTML(fragment: DocumentFragment): string {
  // Get document reference (browser or jsdom)
  const doc = typeof document !== 'undefined' ? document : (fragment as any).ownerDocument

  if (!doc) {
    throw new Error('Cannot serialize: document not available')
  }

  // Create temporary div to hold fragment
  const div = doc.createElement('div')
  div.appendChild(fragment.cloneNode(true))

  // Return innerHTML
  return div.innerHTML
}
