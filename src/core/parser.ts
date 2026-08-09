/**
 * @lpm.dev/neo.sanitize - HTML Parser
 *
 * Browsers use their document runtime. Node.js and Web Workers must supply a
 * DOM runtime when they do not expose `document` and `DOMParser` globally.
 */

import type { DOMParserLike, DOMRuntime } from '../types.js'

const PARSER_CACHE = new WeakMap<DOMRuntime['DOMParser'], DOMParserLike>()
let cachedGlobalDocument: Document | undefined
let cachedGlobalParser: DOMRuntime['DOMParser'] | undefined
let cachedGlobalRuntime: DOMRuntime | undefined

/**
 * Check if the current environment has browser DOM APIs.
 */
export function isBrowser(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof document !== 'undefined' &&
    typeof DOMParser !== 'undefined'
  )
}

/**
 * Check if the current environment is Node.js.
 */
export function isNode(): boolean {
  return (
    typeof process !== 'undefined' &&
    process.versions !== undefined &&
    process.versions.node !== undefined
  )
}

/**
 * Resolve an explicit runtime or the DOM APIs from the current browser.
 */
export function resolveDOMRuntime(runtime?: DOMRuntime): DOMRuntime {
  if (runtime) {
    if (
      !runtime.document ||
      typeof runtime.document.createDocumentFragment !== 'function' ||
      typeof runtime.document.createElement !== 'function' ||
      typeof runtime.DOMParser !== 'function'
    ) {
      throw new TypeError(
        '@lpm.dev/neo.sanitize: The DOM runtime is not compatible. ' +
          'Pass an object with document and DOMParser from the same DOM implementation.'
      )
    }

    return runtime
  }

  if (typeof document !== 'undefined' && typeof DOMParser !== 'undefined') {
    if (
      cachedGlobalRuntime &&
      cachedGlobalDocument === document &&
      cachedGlobalParser === DOMParser
    ) {
      return cachedGlobalRuntime
    }

    cachedGlobalDocument = document
    cachedGlobalParser = DOMParser
    cachedGlobalRuntime = { document, DOMParser }
    return cachedGlobalRuntime
  }

  const environment = isNode() ? 'Node.js' : 'this environment'
  throw new Error(
    `@lpm.dev/neo.sanitize: No DOM runtime is available in ${environment}. ` +
      'Pass { document, DOMParser } as the runtime argument. Web Workers must supply a compatible DOM implementation.'
  )
}

/**
 * Parse an HTML string into a document fragment.
 *
 * @param html - HTML string to parse
 * @param runtime - Optional DOM runtime for Node.js or a Web Worker
 */
export function parseHTML(html: string, runtime?: DOMRuntime): DocumentFragment {
  const dom = resolveDOMRuntime(runtime)
  return parseHTMLWithRuntime(html, dom)
}

/**
 * Parse HTML with a previously resolved runtime.
 */
export function parseHTMLWithRuntime(html: string, dom: DOMRuntime): DocumentFragment {
  const parsedDocument = parseDocumentWithRuntime(html, dom)
  const fragment = dom.document.createDocumentFragment()

  while (parsedDocument.body.firstChild) {
    fragment.appendChild(parsedDocument.body.firstChild)
  }

  return fragment
}

/**
 * Parse HTML into a document with a previously resolved runtime.
 */
export function parseDocumentWithRuntime(html: string, dom: DOMRuntime): Document {
  let parser = PARSER_CACHE.get(dom.DOMParser)
  if (!parser) {
    parser = new dom.DOMParser()
    PARSER_CACHE.set(dom.DOMParser, parser)
  }

  const parsedDocument = parser.parseFromString(html, 'text/html')

  if (!parsedDocument?.body) {
    throw new TypeError(
      '@lpm.dev/neo.sanitize: The DOM runtime parser did not return an HTML document with a body.'
    )
  }

  return parsedDocument
}

/**
 * Serialize a document fragment to an HTML string.
 */
export function serializeHTML(fragment: DocumentFragment): string {
  const ownerDocument = fragment.ownerDocument

  if (!ownerDocument) {
    throw new Error('@lpm.dev/neo.sanitize: Cannot serialize a fragment without an owner document.')
  }

  const container = ownerDocument.createElement('div')
  container.appendChild(fragment.cloneNode(true))
  return container.innerHTML
}

/**
 * Serialize a final result without cloning a fragment that will be discarded.
 */
export function consumeAndSerializeHTML(fragment: DocumentFragment): string {
  const ownerDocument = fragment.ownerDocument

  if (!ownerDocument) {
    throw new Error('@lpm.dev/neo.sanitize: Cannot serialize a fragment without an owner document.')
  }

  const container = ownerDocument.createElement('div')
  container.appendChild(fragment)
  return container.innerHTML
}
