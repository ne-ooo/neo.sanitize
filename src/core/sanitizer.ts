/**
 * @lpm.dev/neo.sanitize - Core Sanitization Engine
 *
 * Main sanitization logic that:
 * 1. Parses HTML to DOM tree
 * 2. Traverses and validates each node
 * 3. Removes dangerous tags, attributes, and protocols
 * 4. Returns sanitized HTML string or DocumentFragment
 */

import type { SanitizeOptions, SanitizeHooks } from '../types.js'
import { DEFAULT_OPTIONS } from '../config/defaults.js'
import { BASIC_SCHEMA, RELAXED_SCHEMA, STRICT_SCHEMA } from '../config/schemas.js'
import { parseHTML, serializeHTML } from './parser.js'
import { isTagAllowed, normalizeTagName, isDangerousTag } from '../validators/tags.js'
import { validateAttribute, normalizeAttributeName } from '../validators/attributes.js'
import { sanitizeMXSS } from '../validators/mxss.js'

/**
 * Sanitize HTML string
 *
 * Main sanitization function that removes dangerous HTML:
 * - Blocks XSS vectors (script tags, event handlers, javascript: URLs)
 * - Whitelists safe tags and attributes
 * - Validates URL protocols
 * - Returns safe HTML
 *
 * @param html - HTML string to sanitize
 * @param options - Sanitization options
 * @returns Sanitized HTML string or DocumentFragment
 *
 * @example
 * sanitize('<p>Hello</p>') // '<p>Hello</p>'
 * sanitize('<p onclick="alert(1)">Hello</p>') // '<p>Hello</p>'
 * sanitize('<script>alert(1)</script>') // ''
 * sanitize('<a href="javascript:alert(1)">Click</a>') // '<a>Click</a>'
 */
export function sanitize(
  html: string,
  options: Partial<SanitizeOptions> = {}
): string | DocumentFragment {
  // Merge with default options (excluding hooks which are handled separately)
  const config: Required<Omit<SanitizeOptions, 'hooks'>> = {
    ...DEFAULT_OPTIONS,
    ...options,
    // Ensure arrays are provided
    allowedTags: options.allowedTags ?? DEFAULT_OPTIONS.allowedTags,
    allowedAttributes: options.allowedAttributes ?? DEFAULT_OPTIONS.allowedAttributes,
    allowedProtocols: options.allowedProtocols ?? DEFAULT_OPTIONS.allowedProtocols,
    forbiddenAttributes: options.forbiddenAttributes ?? DEFAULT_OPTIONS.forbiddenAttributes,
    allowAllAttributes: options.allowAllAttributes ?? DEFAULT_OPTIONS.allowAllAttributes,
  }

  // Early return for empty input
  if (!html || typeof html !== 'string') {
    return config.returnString ? '' : document.createDocumentFragment()
  }

  // Call beforeSanitize hook (Phase 2)
  let processedHtml = html
  if (options.hooks?.beforeSanitize) {
    const hookResult = options.hooks.beforeSanitize(html)
    if (typeof hookResult === 'string') {
      processedHtml = hookResult
    }
  }

  // Parse HTML to DOM
  const fragment = parseHTML(processedHtml)

  // Sanitize the DOM tree (with hooks support)
  sanitizeNode(fragment, config, options.hooks)

  // Check for and remove mXSS patterns (Phase 2)
  if (config.detectMXSS) {
    sanitizeMXSS(fragment, true)
  }

  // Call afterSanitize hook (Phase 2)
  let finalFragment = fragment
  if (options.hooks?.afterSanitize) {
    const hookResult = options.hooks.afterSanitize(fragment)
    if (hookResult instanceof DocumentFragment) {
      finalFragment = hookResult
    }
  }

  // Return as string or DocumentFragment
  if (config.returnString) {
    return serializeHTML(finalFragment)
  }

  return finalFragment
}

/**
 * Sanitize a DOM node and its children (recursive)
 *
 * Traverses the DOM tree and:
 * - Removes dangerous tags
 * - Removes dangerous attributes
 * - Keeps text content (if keepTextContent is true)
 *
 * @param node - Node to sanitize
 * @param config - Sanitization configuration
 */
function sanitizeNode(node: Node, config: Required<Omit<SanitizeOptions, 'hooks'>>, hooks?: SanitizeHooks): void {
  // Get all child nodes (NodeList)
  const children = Array.from(node.childNodes)

  for (const child of children) {
    // Handle Element nodes (tags)
    if (child.nodeType === Node.ELEMENT_NODE) {
      const element = child as Element
      const tagName = normalizeTagName(element.tagName)

      // Check if tag is allowed
      const tagAllowed = isTagAllowed(tagName, config.allowedTags)

      if (!tagAllowed) {
        // Tag is not allowed
        // SECURITY: Never keep text content from dangerous tags (script, style, etc.)
        const dangerous = isDangerousTag(tagName)

        if (!dangerous && (config.stripTags || config.keepTextContent)) {
          // Keep text content for non-dangerous tags (like form, input, button)
          const textContent = element.textContent
          if (textContent) {
            const textNode = document.createTextNode(textContent)
            node.replaceChild(textNode, element)
          } else {
            node.removeChild(element)
          }
        } else {
          // Remove dangerous tags entirely (script, style, iframe, etc.)
          node.removeChild(element)
        }
        continue
      }

      // Call onElement hook (Phase 2)
      if (hooks?.onElement) {
        const hookResult = hooks.onElement(element)
        if (hookResult === false) {
          // Hook requested element removal
          node.removeChild(element)
          continue
        }
      }

      // Tag is allowed, sanitize attributes
      sanitizeAttributes(element, tagName, config, hooks)

      // Recursively sanitize children
      sanitizeNode(element, config, hooks)
    }
    // Handle Text nodes (keep as-is)
    else if (child.nodeType === Node.TEXT_NODE) {
      // Text nodes are safe, no action needed
      continue
    }
    // Handle Comment nodes (remove)
    else if (child.nodeType === Node.COMMENT_NODE) {
      node.removeChild(child)
    }
    // Handle other nodes (remove to be safe)
    else {
      node.removeChild(child)
    }
  }
}

/**
 * Sanitize attributes of an element
 *
 * Removes dangerous attributes:
 * - Event handlers (onclick, onerror, etc.)
 * - Dangerous URL protocols (javascript:, data:, etc.)
 * - Forbidden attributes (formaction, etc.)
 *
 * @param element - Element to sanitize
 * @param tagName - Tag name (lowercase)
 * @param config - Sanitization configuration
 * @param hooks - Optional hooks for customization (Phase 2)
 */
function sanitizeAttributes(element: Element, tagName: string, config: Required<Omit<SanitizeOptions, 'hooks'>>, hooks?: SanitizeHooks): void {
  // Get all attributes
  const attributes = Array.from(element.attributes)

  for (const attr of attributes) {
    let attrName = attr.name
    let attrValue = attr.value

    // Normalize attribute name
    if (config.lowercaseAttributes) {
      attrName = normalizeAttributeName(attrName)
    }

    // Call onAttribute hook (Phase 2)
    if (hooks?.onAttribute) {
      const hookResult = hooks.onAttribute(element, attrName, attrValue)
      if (hookResult === false) {
        // Hook requested attribute removal
        element.removeAttribute(attr.name)
        continue
      }
    }

    // Validate attribute
    const validation = validateAttribute(
      tagName,
      attrName,
      attrValue,
      config.allowedAttributes,
      config
    )

    if (!validation.allowed) {
      // Attribute is not allowed, remove it
      element.removeAttribute(attr.name)
    } else if (validation.sanitizedValue !== undefined) {
      // Attribute value was sanitized, update it
      element.setAttribute(attr.name, validation.sanitizedValue)
    }
  }
}

/**
 * Create a reusable sanitizer instance with preset configuration
 *
 * Useful for sanitizing multiple HTML strings with the same options.
 * Avoids re-merging options on every call.
 *
 * @param options - Sanitization options
 * @returns Sanitizer instance
 *
 * @example
 * const sanitizer = createSanitizer({ allowClassAttribute: true })
 * sanitizer.sanitize('<p class="text">Hello</p>') // '<p class="text">Hello</p>'
 * sanitizer.sanitize('<script>alert(1)</script>') // ''
 */
export function createSanitizer(options: Partial<SanitizeOptions> = {}) {
  // Merge options once
  const config: Required<Omit<SanitizeOptions, 'hooks'>> = {
    ...DEFAULT_OPTIONS,
    ...options,
    allowedTags: options.allowedTags ?? DEFAULT_OPTIONS.allowedTags,
    allowedAttributes: options.allowedAttributes ?? DEFAULT_OPTIONS.allowedAttributes,
    allowedProtocols: options.allowedProtocols ?? DEFAULT_OPTIONS.allowedProtocols,
    forbiddenAttributes: options.forbiddenAttributes ?? DEFAULT_OPTIONS.forbiddenAttributes,
    allowAllAttributes: options.allowAllAttributes ?? DEFAULT_OPTIONS.allowAllAttributes,
  }

  return {
    /**
     * Sanitize HTML with preset configuration
     */
    sanitize(html: string): string | DocumentFragment {
      return sanitize(html, config)
    },

    /**
     * Get current configuration
     */
    getConfig(): Readonly<Required<Omit<SanitizeOptions, 'hooks'>>> {
      return config
    },

    /**
     * Update configuration
     */
    updateConfig(newOptions: Partial<SanitizeOptions>): void {
      Object.assign(config, newOptions)
    },
  }
}

/**
 * Convenience function: Sanitize with BASIC schema
 */
export function sanitizeBasic(html: string): string {
  return sanitize(html, BASIC_SCHEMA) as string
}

/**
 * Convenience function: Sanitize with RELAXED schema
 */
export function sanitizeRelaxed(html: string): string {
  return sanitize(html, RELAXED_SCHEMA) as string
}

/**
 * Convenience function: Sanitize with STRICT schema
 */
export function sanitizeStrict(html: string): string {
  return sanitize(html, STRICT_SCHEMA) as string
}
