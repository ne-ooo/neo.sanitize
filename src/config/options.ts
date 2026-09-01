import type {
  ResolvedSanitizeOptions as PublicResolvedSanitizeOptions,
  SanitizeOptions,
} from '../types.js'
import { deepFreeze } from '../utils/object.js'
import { resolveInsertionContext } from '../utils/context.js'

export type ResolvedSanitizeOptions = PublicResolvedSanitizeOptions

/**
 * Read an own data property without consulting a polluted prototype or
 * invoking an accessor supplied by an untrusted configuration object.
 */
export function readOwnOption<K extends keyof SanitizeOptions>(
  options: Partial<SanitizeOptions>,
  key: K
): SanitizeOptions[K] | undefined {
  const descriptor = Object.getOwnPropertyDescriptor(options, key)
  return descriptor && 'value' in descriptor
    ? (descriptor.value as SanitizeOptions[K])
    : undefined
}

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
  const allowedAttributes =
    readOwnOption(options, 'allowedAttributes') ?? base.allowedAttributes
  const clonedAttributes = Object.create(null) as Record<string, string[]>

  for (const tagName of Object.keys(allowedAttributes)) {
    const attributes = allowedAttributes[tagName]
    if (attributes) clonedAttributes[tagName] = [...attributes]
  }

  return {
    allowedTags: [...(readOwnOption(options, 'allowedTags') ?? base.allowedTags)],
    allowedAttributes: clonedAttributes,
    allowedProtocols: [
      ...(readOwnOption(options, 'allowedProtocols') ?? base.allowedProtocols),
    ],
    forbiddenAttributes: [
      ...(readOwnOption(options, 'forbiddenAttributes') ?? base.forbiddenAttributes),
    ],
    allowAllAttributes: [
      ...(readOwnOption(options, 'allowAllAttributes') ?? base.allowAllAttributes),
    ],
    allowDataAttributes:
      readOwnOption(options, 'allowDataAttributes') ?? base.allowDataAttributes,
    allowAriaAttributes:
      readOwnOption(options, 'allowAriaAttributes') ?? base.allowAriaAttributes,
    allowClassAttribute:
      readOwnOption(options, 'allowClassAttribute') ?? base.allowClassAttribute,
    allowIdAttribute:
      readOwnOption(options, 'allowIdAttribute') ?? base.allowIdAttribute,
    allowStyleAttribute:
      readOwnOption(options, 'allowStyleAttribute') ?? base.allowStyleAttribute,
    allowCustomElements:
      readOwnOption(options, 'allowCustomElements') ?? base.allowCustomElements,
    stripTags: readOwnOption(options, 'stripTags') ?? base.stripTags,
    keepTextContent:
      readOwnOption(options, 'keepTextContent') ?? base.keepTextContent,
    lowercaseTags: readOwnOption(options, 'lowercaseTags') ?? base.lowercaseTags,
    lowercaseAttributes:
      readOwnOption(options, 'lowercaseAttributes') ?? base.lowercaseAttributes,
    returnString: readOwnOption(options, 'returnString') ?? base.returnString,
    insertionContext: resolveInsertionContext(
      readOwnOption(options, 'insertionContext'),
      base.insertionContext
    ),
    maxInputLength: resolveLimit(
      readOwnOption(options, 'maxInputLength'),
      base.maxInputLength
    ),
    maxDOMNodes: resolveLimit(
      readOwnOption(options, 'maxDOMNodes'),
      base.maxDOMNodes
    ),
    maxDOMDepth: resolveLimit(
      readOwnOption(options, 'maxDOMDepth'),
      base.maxDOMDepth
    ),
    preventDOMClobbering:
      readOwnOption(options, 'preventDOMClobbering') ?? base.preventDOMClobbering,
    detectMXSS: readOwnOption(options, 'detectMXSS') ?? base.detectMXSS,
    strictCSSValidation:
      readOwnOption(options, 'strictCSSValidation') ?? base.strictCSSValidation,
  }
}

/**
 * Return a detached and recursively frozen configuration snapshot.
 */
export function snapshotOptions(config: ResolvedSanitizeOptions): ResolvedSanitizeOptions {
  return deepFreeze(mergeOptions(config))
}
