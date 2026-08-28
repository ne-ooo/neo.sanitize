/**
 * @lpm.dev/neo.sanitize - HTML Parser
 *
 * Browsers use their document runtime. Node.js and Web Workers must supply a
 * DOM runtime when they do not expose `document` and `DOMParser` globally.
 */

import type {
  DOMParserLike,
  DOMRuntime,
  HTMLInsertionContext,
} from '../types.js'
import {
  appendNode,
  cloneDOMNode,
  createDocumentFragment,
  createElement,
  getDocumentBody,
  getLastChild,
  getOwnerDocument,
  setElementHTML,
} from '../utils/dom.js'
import { resolveInsertionContext } from '../utils/context.js'

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
export function parseHTML(
  html: string,
  runtime?: DOMRuntime,
  insertionContext: HTMLInsertionContext = 'body'
): DocumentFragment {
  const dom = resolveDOMRuntime(runtime)
  return parseHTMLWithRuntime(html, dom, insertionContext)
}

/**
 * Parse HTML with a previously resolved runtime.
 */
export function parseHTMLWithRuntime(
  html: string,
  dom: DOMRuntime,
  insertionContext: HTMLInsertionContext = 'body'
): DocumentFragment {
  const source = parseHTMLContextWithRuntime(html, dom, insertionContext)
  const parsedDocument = getOwnerDocument(source)
  if (!parsedDocument) {
    throw new TypeError(
      '@lpm.dev/neo.sanitize: The parsed insertion context has no owner document.'
    )
  }

  // Keep untrusted nodes in the detached parser document. Adopting raw nodes
  // into the live document can start resource loads and fire event handlers
  // before the sanitizer has removed active attributes.
  const reversed = createDocumentFragment(parsedDocument)

  // Remove from the end so array-backed DOM implementations do not shift all
  // remaining siblings for every move. Reverse twice to retain source order.
  let child = getLastChild(source)
  while (child) {
    appendNode(reversed, child)
    child = getLastChild(source)
  }

  const fragment = createDocumentFragment(parsedDocument)
  child = getLastChild(reversed)
  while (child) {
    appendNode(fragment, child)
    child = getLastChild(reversed)
  }

  return fragment
}

/**
 * Parse HTML into its detached receiving element without moving its children.
 * The sanitizer uses this path to avoid superlinear top-level node removal in
 * DOM implementations backed by arrays.
 */
export function parseHTMLContextWithRuntime(
  html: string,
  dom: DOMRuntime,
  insertionContext: HTMLInsertionContext = 'body'
): HTMLElement {
  const context = resolveInsertionContext(insertionContext, 'body')
  const parsedDocument = parseDocumentWithRuntime('', dom)
  const source =
    context === 'body'
      ? (getDocumentBody(parsedDocument) as HTMLBodyElement)
      : createElement(parsedDocument, context)

  setElementHTML(source, html)
  return source as HTMLElement
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

  let parsedDocument: Document
  try {
    parsedDocument = parser.parseFromString(html, 'text/html')
  } catch (cause) {
    throw new Error('@lpm.dev/neo.sanitize: The DOM runtime failed to parse the HTML input.', {
      cause,
    })
  }

  if (!parsedDocument || !getDocumentBody(parsedDocument)) {
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
  const ownerDocument = getOwnerDocument(fragment)

  if (!ownerDocument) {
    throw new Error('@lpm.dev/neo.sanitize: Cannot serialize a fragment without an owner document.')
  }

  const container = createElement(ownerDocument, 'div')
  appendNode(container, cloneDOMNode(fragment, true))
  return container.innerHTML
}

/**
 * Serialize a final result without cloning a fragment that will be discarded.
 */
export function consumeAndSerializeHTML(fragment: DocumentFragment): string {
  const ownerDocument = getOwnerDocument(fragment)

  if (!ownerDocument) {
    throw new Error('@lpm.dev/neo.sanitize: Cannot serialize a fragment without an owner document.')
  }

  const container = createElement(ownerDocument, 'div')
  appendNode(container, fragment)
  return container.innerHTML
}
