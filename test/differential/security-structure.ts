import { parseHTML } from '../../src/core/parser.js'
import type {
  DOMRuntime,
  HTMLInsertionContext,
} from '../../src/types.js'

/** Return a text-insensitive DOM signature for cross-runtime comparisons. */
export function getHTMLSecurityStructure(
  html: string,
  runtime: DOMRuntime,
  insertionContext: HTMLInsertionContext
): string {
  const fragment = parseHTML(html, runtime, insertionContext)
  const elements = Array.from(fragment.querySelectorAll('*'))
  const elementIndexes = new Map(
    elements.map((element, index) => [element, index] as const)
  )

  return JSON.stringify(
    elements.map((element) => ({
      tag: element.localName.toLowerCase(),
      namespace: element.namespaceURI,
      parentIndex: element.parentElement
        ? (elementIndexes.get(element.parentElement) ?? null)
        : null,
      attributes: Array.from(element.attributes)
        .map(({ name, value }) => [name.toLowerCase(), value] as const)
        .sort(([left], [right]) => left.localeCompare(right)),
    }))
  )
}
