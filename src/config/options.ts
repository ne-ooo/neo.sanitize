import type { SanitizeOptions } from '../types.js'
import { deepFreeze } from '../utils/object.js'

export type ResolvedSanitizeOptions = Required<Omit<SanitizeOptions, 'hooks'>>

function resolveLimit(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback
  if (!Number.isFinite(value) || value < 0) return fallback
  return Math.floor(value)
}

/**
 * Merge options into a resolved configuration without retaining caller-owned
 * arrays or attribute maps.
 */
export function mergeOptions(
  base: ResolvedSanitizeOptions,
  options: Partial<SanitizeOptions> = {}
): ResolvedSanitizeOptions {
  const allowedAttributes = options.allowedAttributes ?? base.allowedAttributes
  const clonedAttributes = Object.create(null) as Record<string, string[]>

  for (const tagName of Object.keys(allowedAttributes)) {
    const attributes = allowedAttributes[tagName]
    if (attributes) clonedAttributes[tagName] = [...attributes]
  }

  return {
    allowedTags: [...(options.allowedTags ?? base.allowedTags)],
    allowedAttributes: clonedAttributes,
    allowedProtocols: [...(options.allowedProtocols ?? base.allowedProtocols)],
    forbiddenAttributes: [...(options.forbiddenAttributes ?? base.forbiddenAttributes)],
    allowAllAttributes: [...(options.allowAllAttributes ?? base.allowAllAttributes)],
    allowDataAttributes: options.allowDataAttributes ?? base.allowDataAttributes,
    allowAriaAttributes: options.allowAriaAttributes ?? base.allowAriaAttributes,
    allowClassAttribute: options.allowClassAttribute ?? base.allowClassAttribute,
    allowIdAttribute: options.allowIdAttribute ?? base.allowIdAttribute,
    allowStyleAttribute: options.allowStyleAttribute ?? base.allowStyleAttribute,
    stripTags: options.stripTags ?? base.stripTags,
    keepTextContent: options.keepTextContent ?? base.keepTextContent,
    lowercaseTags: options.lowercaseTags ?? base.lowercaseTags,
    lowercaseAttributes: options.lowercaseAttributes ?? base.lowercaseAttributes,
    returnString: options.returnString ?? base.returnString,
    maxInputLength: resolveLimit(options.maxInputLength, base.maxInputLength),
    maxDOMNodes: resolveLimit(options.maxDOMNodes, base.maxDOMNodes),
    maxDOMDepth: resolveLimit(options.maxDOMDepth, base.maxDOMDepth),
    preventDOMClobbering: options.preventDOMClobbering ?? base.preventDOMClobbering,
    detectMXSS: options.detectMXSS ?? base.detectMXSS,
    strictCSSValidation: options.strictCSSValidation ?? base.strictCSSValidation,
  }
}

/**
 * Return a detached and recursively frozen configuration snapshot.
 */
export function snapshotOptions(config: ResolvedSanitizeOptions): ResolvedSanitizeOptions {
  return deepFreeze(mergeOptions(config))
}
