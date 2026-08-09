/**
 * @lpm.dev/neo.sanitize - Core Sanitization Engine
 */

import type {
  DOMRuntime,
  SanitizeHooks,
  SanitizeOptions,
  Sanitizer,
} from '../types.js'
import { DEFAULT_OPTIONS } from '../config/defaults.js'
import { mergeOptions, snapshotOptions } from '../config/options.js'
import type { ResolvedSanitizeOptions } from '../config/options.js'
import { BASIC_SCHEMA, RELAXED_SCHEMA, STRICT_SCHEMA } from '../config/schemas.js'
import {
  consumeAndSerializeHTML,
  parseDocumentWithRuntime,
  parseHTMLWithRuntime,
  resolveDOMRuntime,
  serializeHTML,
} from './parser.js'
import { isDangerousTagNormalized } from '../validators/tags.js'
import { validateAttributeNormalized } from '../validators/attributes.js'
import type { AttributeValidationPolicy } from '../validators/attributes.js'
import { sanitizeMXSS } from '../validators/mxss.js'

const ELEMENT_NODE = 1
const TEXT_NODE = 3
const COMMENT_NODE = 8
const DOCUMENT_FRAGMENT_NODE = 11
const MAX_MXSS_STABILIZATION_PASSES = 3
const EMPTY_OPTIONS: Partial<SanitizeOptions> = Object.freeze({})

interface SanitizationPolicy {
  config: ResolvedSanitizeOptions
  allowedTags: ReadonlySet<string>
  attributes: AttributeValidationPolicy
}

const POLICY_CACHE = new WeakMap<ResolvedSanitizeOptions, SanitizationPolicy>()

function getPolicy(config: ResolvedSanitizeOptions): SanitizationPolicy {
  const cached = POLICY_CACHE.get(config)
  if (cached) return cached

  const allowedAttributes = new Map<string, ReadonlySet<string>>()
  for (const [tagName, attributes] of Object.entries(config.allowedAttributes)) {
    allowedAttributes.set(tagName, new Set(attributes))
  }

  const policy: SanitizationPolicy = {
    config,
    allowedTags: new Set(config.allowedTags),
    attributes: {
      forbiddenAttributes: new Set(config.forbiddenAttributes),
      allowAllAttributes: new Set(config.allowAllAttributes),
      allowedAttributes,
      allowedProtocols: new Set(config.allowedProtocols),
    },
  }
  POLICY_CACHE.set(config, policy)
  return policy
}

function resolveOptions(options: Partial<SanitizeOptions>): ResolvedSanitizeOptions {
  if (
    options === EMPTY_OPTIONS ||
    options === DEFAULT_OPTIONS ||
    options === BASIC_SCHEMA ||
    options === RELAXED_SCHEMA ||
    options === STRICT_SCHEMA
  ) {
    return options === EMPTY_OPTIONS
      ? DEFAULT_OPTIONS
      : (options as ResolvedSanitizeOptions)
  }

  const prototype = Object.getPrototypeOf(options)
  if (prototype === Object.prototype || prototype === null) {
    let hasOwnOption = false
    for (const key in options) {
      if (Object.prototype.hasOwnProperty.call(options, key)) {
        hasOwnOption = true
        break
      }
    }
    if (!hasOwnOption) return DEFAULT_OPTIONS
  }

  return mergeOptions(DEFAULT_OPTIONS, options)
}

/**
 * Sanitize an HTML string.
 *
 * @param html - HTML string to sanitize
 * @param options - Sanitization options
 * @param runtime - Optional DOM runtime for Node.js or a Web Worker
 */
export function sanitize(
  html: string,
  options: Partial<SanitizeOptions> = EMPTY_OPTIONS,
  runtime?: DOMRuntime
): string | DocumentFragment {
  const config = resolveOptions(options)
  return sanitizeWithPolicy(html, getPolicy(config), options.hooks, runtime)
}

function sanitizeWithPolicy(
  html: string,
  policy: SanitizationPolicy,
  hooks: SanitizeHooks | undefined,
  runtime: DOMRuntime | undefined
): string | DocumentFragment {
  const config = policy.config

  if (!html || typeof html !== 'string') {
    if (config.returnString) {
      return ''
    }

    return resolveDOMRuntime(runtime).document.createDocumentFragment()
  }

  let processedHtml = html
  if (hooks?.beforeSanitize) {
    const hookResult = hooks.beforeSanitize(html)
    if (typeof hookResult === 'string') {
      processedHtml = hookResult
    }
  }

  const dom = resolveDOMRuntime(runtime)
  const useDirectStringPath =
    config.returnString &&
    !config.detectMXSS &&
    !hooks?.onElement &&
    !hooks?.onAttribute &&
    !hooks?.afterSanitize

  if (useDirectStringPath) {
    const parsedDocument = parseDocumentWithRuntime(processedHtml, dom)
    sanitizeNode(parsedDocument.body, policy)
    return parsedDocument.body.innerHTML
  }

  const fragment = parseHTMLWithRuntime(processedHtml, dom)

  // User hooks run only in this pass.
  sanitizeNode(fragment, policy, hooks)

  if (config.detectMXSS && hooks?.afterSanitize) {
    sanitizeMXSS(fragment, true)
  }

  let finalFragment = fragment
  if (hooks?.afterSanitize) {
    const hookResult = hooks.afterSanitize(fragment)
    if (isDocumentFragment(hookResult)) {
      finalFragment = hookResult
    }
  }

  if (hooks?.onElement || hooks?.onAttribute || hooks?.afterSanitize) {
    // Hooks can change nodes that the first traversal already processed. This
    // pass has no hooks, so every current element and attribute is revalidated.
    sanitizeNode(finalFragment, policy)
  }

  if (config.detectMXSS) {
    sanitizeMXSS(finalFragment, true)
    finalFragment = stabilizeMXSS(finalFragment, policy, dom)
  }

  if (!config.returnString) return finalFragment

  const hooksCanRetainNodes = Boolean(
    hooks?.onElement || hooks?.onAttribute || hooks?.afterSanitize
  )
  return hooksCanRetainNodes
    ? serializeHTML(finalFragment)
    : consumeAndSerializeHTML(finalFragment)
}

/**
 * Sanitize a DOM node and its descendants.
 */
function sanitizeNode(
  node: Node,
  policy: SanitizationPolicy,
  hooks?: SanitizeHooks
): void {
  const config = policy.config
  let child = node.firstChild

  while (child) {
    const next = child.nextSibling
    if (child.nodeType === ELEMENT_NODE) {
      const element = child as Element
      const tagName = element.localName.toLowerCase()

      if (isDangerousTagNormalized(tagName)) {
        node.removeChild(element)
        child = next
        continue
      }

      if (!policy.allowedTags.has(tagName)) {
        if (config.stripTags || config.keepTextContent) {
          sanitizeNode(element, policy, hooks)
          unwrapElement(element)
        } else {
          node.removeChild(element)
        }
        child = next
        continue
      }

      if (hooks?.onElement) {
        const hookResult = hooks.onElement(element)
        if (hookResult === false) {
          node.removeChild(element)
          child = next
          continue
        }
      }

      sanitizeAttributes(element, tagName, policy, hooks)
      sanitizeNode(element, policy, hooks)

      // stripTags applies to allowed elements as well as unknown wrappers.
      if (config.stripTags) {
        unwrapElement(element)
      }
    } else if (child.nodeType === TEXT_NODE) {
      // Text nodes are safe.
    } else if (child.nodeType === COMMENT_NODE) {
      node.removeChild(child)
    } else {
      node.removeChild(child)
    }

    child = next
  }
}

/**
 * Move an element's sanitized children into its parent, then remove the
 * element itself.
 */
function unwrapElement(element: Element): void {
  const parent = element.parentNode
  if (!parent) {
    return
  }

  while (element.firstChild) {
    parent.insertBefore(element.firstChild, element)
  }
  parent.removeChild(element)
}

/**
 * Sanitize all current attributes of an element.
 */
function sanitizeAttributes(
  element: Element,
  tagName: string,
  policy: SanitizationPolicy,
  hooks?: SanitizeHooks
): void {
  if (hooks?.onAttribute) {
    const attributes = Array.from(element.attributes)
    for (const attr of attributes) {
      sanitizeAttribute(element, tagName, attr, policy, hooks)
    }
    return
  }

  let index = 0
  while (index < element.attributes.length) {
    const attr = element.attributes.item(index)
    if (!attr) break

    const removed = sanitizeAttribute(element, tagName, attr, policy)
    if (!removed) index++
  }
}

function sanitizeAttribute(
  element: Element,
  tagName: string,
  attr: Attr,
  policy: SanitizationPolicy,
  hooks?: SanitizeHooks
): boolean {
  const config = policy.config
  const attrName = config.lowercaseAttributes ? attr.name.toLowerCase() : attr.name
  const attrValue = attr.value

  if (hooks?.onAttribute) {
    const hookResult = hooks.onAttribute(element, attrName, attrValue)
    if (hookResult === false) {
      element.removeAttribute(attr.name)
      return true
    }
  }

  const validation = validateAttributeNormalized(
    tagName,
    attrName,
    attrValue,
    config.allowedAttributes,
    config,
    policy.attributes
  )

  if (!validation.allowed) {
    element.removeAttribute(attr.name)
    return true
  }

  if (validation.sanitizedValue !== undefined) {
    element.setAttribute(attr.name, validation.sanitizedValue)
  }
  return false
}

/**
 * Reparse and sanitize output until serialization is stable.
 *
 * If stability does not occur within the pass limit, return an empty fragment.
 */
function stabilizeMXSS(
  fragment: DocumentFragment,
  policy: SanitizationPolicy,
  runtime: DOMRuntime
): DocumentFragment {
  let serialized = serializeHTML(fragment)

  for (let pass = 0; pass < MAX_MXSS_STABILIZATION_PASSES; pass++) {
    const reparsed = parseHTMLWithRuntime(serialized, runtime)
    sanitizeNode(reparsed, policy)
    sanitizeMXSS(reparsed, true)

    const nextSerialized = serializeHTML(reparsed)
    if (nextSerialized === serialized) {
      return reparsed
    }

    serialized = nextSerialized
  }

  return runtime.document.createDocumentFragment()
}

function isDocumentFragment(value: unknown): value is DocumentFragment {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Node).nodeType === DOCUMENT_FRAGMENT_NODE &&
    'childNodes' in value
  )
}

/**
 * Create a reusable sanitizer with preset configuration.
 */
export function createSanitizer(
  options: Partial<SanitizeOptions> = EMPTY_OPTIONS,
  runtime?: DOMRuntime
): Sanitizer {
  let config = resolveOptions(options)
  let hooks = options.hooks

  return {
    sanitize(html: string): string | DocumentFragment {
      return sanitizeWithPolicy(html, getPolicy(config), hooks, runtime)
    },

    getConfig(): Readonly<ResolvedSanitizeOptions> {
      return snapshotOptions(config)
    },

    updateConfig(newOptions: Partial<SanitizeOptions>): void {
      config = mergeOptions(config, newOptions)
      if (Object.prototype.hasOwnProperty.call(newOptions, 'hooks')) {
        hooks = newOptions.hooks
      }
    },
  }
}

export function sanitizeBasic(html: string, runtime?: DOMRuntime): string {
  return sanitizeWithPolicy(html, getPolicy(BASIC_SCHEMA), undefined, runtime) as string
}

export function sanitizeRelaxed(html: string, runtime?: DOMRuntime): string {
  return sanitizeWithPolicy(html, getPolicy(RELAXED_SCHEMA), undefined, runtime) as string
}

export function sanitizeStrict(html: string, runtime?: DOMRuntime): string {
  return sanitizeWithPolicy(html, getPolicy(STRICT_SCHEMA), undefined, runtime) as string
}
