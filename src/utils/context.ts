import type { HTMLInsertionContext } from '../types.js'
import { deepFreeze } from './object.js'

export const HTML_INSERTION_CONTEXTS: readonly HTMLInsertionContext[] = deepFreeze([
  'body',
  'div',
  'table',
  'caption',
  'colgroup',
  'thead',
  'tbody',
  'tfoot',
  'tr',
  'td',
  'th',
  'select',
  'optgroup',
  'option',
])

const HTML_INSERTION_CONTEXT_SET = new Set<string>(HTML_INSERTION_CONTEXTS)

export function resolveInsertionContext(
  value: HTMLInsertionContext | undefined,
  fallback: HTMLInsertionContext
): HTMLInsertionContext {
  if (value === undefined) return fallback
  if (HTML_INSERTION_CONTEXT_SET.has(value)) return value

  throw new RangeError(
    `@lpm.dev/neo.sanitize: Unsupported insertion context "${String(value)}".`
  )
}
