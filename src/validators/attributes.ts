/**
 * @lpm.dev/neo.sanitize - Attribute Validation
 *
 * Validates HTML attributes to prevent XSS attacks via:
 * - Event handlers (onclick, onerror, onload, etc.)
 * - Dangerous URL protocols (javascript:, data:, vbscript:)
 * - DOM clobbering (id/name attributes that shadow DOM APIs)
 * - CSS expressions (style attribute with expression())
 */

import type { AttributeValidationResult, SanitizeOptions } from '../types.js'
import {
  FORBIDDEN_ATTRIBUTES,
  EVENT_HANDLER_REGEX,
  DATA_ATTRIBUTE_REGEX,
  ARIA_ATTRIBUTE_REGEX,
  URL_ATTRIBUTES,
  DEFAULT_ALLOWED_ATTRIBUTES,
} from '../utils/constants.js'
import { sanitizeURL, isSafeURL } from './protocols.js'
import { validateDomClobbering } from './dom-clobbering.js'
import { validateStyleAttribute } from './css.js'

/**
 * Normalize attribute name to lowercase
 *
 * Attribute names are case-insensitive in HTML.
 *
 * @param attrName - Attribute name to normalize
 * @returns Normalized attribute name (lowercase)
 *
 * @example
 * normalizeAttributeName('onClick') // 'onclick'
 * normalizeAttributeName('DATA-VALUE') // 'data-value'
 */
export function normalizeAttributeName(attrName: string): string {
  return attrName.toLowerCase().trim()
}

/**
 * Check if an attribute is an event handler
 *
 * Matches attributes like: onclick, onerror, onload, etc.
 *
 * @param attrName - Attribute name to check (case-insensitive)
 * @returns True if attribute is an event handler
 *
 * @example
 * isEventHandler('onclick') // true
 * isEventHandler('ONERROR') // true
 * isEventHandler('class') // false
 */
export function isEventHandler(attrName: string): boolean {
  const normalized = normalizeAttributeName(attrName)

  // Check if in forbidden list (faster)
  if (FORBIDDEN_ATTRIBUTES.includes(normalized)) {
    return true
  }

  // Check with regex (fallback for unlisted event handlers)
  return EVENT_HANDLER_REGEX.test(normalized)
}

/**
 * Check if an attribute is a data-* attribute
 *
 * Matches attributes like: data-id, data-value, data-test
 *
 * @param attrName - Attribute name to check (case-insensitive)
 * @returns True if attribute is a data attribute
 *
 * @example
 * isDataAttribute('data-id') // true
 * isDataAttribute('DATA-VALUE') // true
 * isDataAttribute('class') // false
 */
export function isDataAttribute(attrName: string): boolean {
  const normalized = normalizeAttributeName(attrName)
  return DATA_ATTRIBUTE_REGEX.test(normalized)
}

/**
 * Check if an attribute is an aria-* attribute
 *
 * Matches attributes like: aria-label, aria-hidden, aria-describedby
 *
 * @param attrName - Attribute name to check (case-insensitive)
 * @returns True if attribute is an ARIA attribute
 *
 * @example
 * isAriaAttribute('aria-label') // true
 * isAriaAttribute('ARIA-HIDDEN') // true
 * isAriaAttribute('class') // false
 */
export function isAriaAttribute(attrName: string): boolean {
  const normalized = normalizeAttributeName(attrName)
  return ARIA_ATTRIBUTE_REGEX.test(normalized)
}

/**
 * Check if an attribute is a URL attribute
 *
 * Matches attributes that accept URLs: href, src, action, etc.
 *
 * @param attrName - Attribute name to check (case-insensitive)
 * @returns True if attribute accepts URLs
 *
 * @example
 * isURLAttribute('href') // true
 * isURLAttribute('src') // true
 * isURLAttribute('class') // false
 */
export function isURLAttribute(attrName: string): boolean {
  const normalized = normalizeAttributeName(attrName)
  return URL_ATTRIBUTES.includes(normalized)
}

/**
 * Check if an attribute is forbidden
 *
 * Checks both the forbidden list and event handler pattern.
 *
 * @param attrName - Attribute name to check (case-insensitive)
 * @param forbiddenAttributes - Additional forbidden attributes
 * @returns True if attribute is forbidden
 *
 * @example
 * isForbiddenAttribute('onclick') // true
 * isForbiddenAttribute('formaction') // true
 * isForbiddenAttribute('class') // false
 */
export function isForbiddenAttribute(
  attrName: string,
  forbiddenAttributes: readonly string[] | string[] = FORBIDDEN_ATTRIBUTES
): boolean {
  const normalized = normalizeAttributeName(attrName)

  // Check if in forbidden list
  if (forbiddenAttributes.includes(normalized)) {
    return true
  }

  // Check if it's an event handler
  if (EVENT_HANDLER_REGEX.test(normalized)) {
    return true
  }

  return false
}

/**
 * Check if an attribute is allowed for a given tag
 *
 * @param tagName - Tag name (lowercase)
 * @param attrName - Attribute name (case-insensitive)
 * @param allowedAttributes - Allowed attributes per tag
 * @param options - Sanitization options
 * @returns True if attribute is allowed for the tag
 *
 * @example
 * isAttributeAllowed('a', 'href') // true
 * isAttributeAllowed('a', 'onclick') // false
 * isAttributeAllowed('div', 'data-id', {}, { allowDataAttributes: true }) // true
 */
export function isAttributeAllowed(
  tagName: string,
  attrName: string,
  allowedAttributes: Readonly<Record<string, readonly string[]>> | Record<string, string[]> = DEFAULT_ALLOWED_ATTRIBUTES,
  options: Partial<SanitizeOptions> = {}
): boolean {
  const normalized = normalizeAttributeName(attrName)

  // Check if forbidden (highest priority)
  if (isForbiddenAttribute(normalized, options.forbiddenAttributes)) {
    return false
  }

  // Check global attribute permissions
  if (normalized === 'class' && options.allowClassAttribute) {
    return true
  }

  if (normalized === 'id' && options.allowIdAttribute) {
    return true
  }

  if (normalized === 'style' && options.allowStyleAttribute) {
    return true
  }

  // Check data-* attributes
  if (isDataAttribute(normalized) && options.allowDataAttributes) {
    return true
  }

  // Check aria-* attributes (default: true)
  if (isAriaAttribute(normalized) && (options.allowAriaAttributes ?? true)) {
    return true
  }

  // Check if tag allows all attributes
  if (options.allowAllAttributes?.includes(tagName)) {
    return true
  }

  // Check if attribute is in allowed list for this tag
  const allowedForTag = allowedAttributes[tagName]
  if (allowedForTag && allowedForTag.includes(normalized)) {
    return true
  }

  return false
}

/**
 * Validate an attribute
 *
 * Comprehensive attribute validation with detailed result:
 * - Normalizes attribute name
 * - Checks if forbidden (event handlers, etc.)
 * - Checks if allowed for the tag
 * - Validates URL protocols for URL attributes
 * - Sanitizes attribute value if needed
 *
 * @param tagName - Tag name (lowercase)
 * @param attrName - Attribute name (case-insensitive)
 * @param attrValue - Attribute value
 * @param allowedAttributes - Allowed attributes per tag
 * @param options - Sanitization options
 * @returns Attribute validation result
 *
 * @example
 * validateAttribute('a', 'href', 'https://example.com')
 * // { allowed: true, attrName: 'href', attrValue: 'https://example.com' }
 *
 * validateAttribute('a', 'onclick', 'alert(1)')
 * // { allowed: false, attrName: 'onclick', attrValue: 'alert(1)', reason: 'Forbidden attribute' }
 *
 * validateAttribute('a', 'href', 'javascript:alert(1)')
 * // { allowed: false, attrName: 'href', attrValue: 'javascript:alert(1)', reason: 'Dangerous URL protocol' }
 */
export function validateAttribute(
  tagName: string,
  attrName: string,
  attrValue: string,
  allowedAttributes: Readonly<Record<string, readonly string[]>> | Record<string, string[]> = DEFAULT_ALLOWED_ATTRIBUTES,
  options: Partial<SanitizeOptions> = {}
): AttributeValidationResult {
  const normalized = normalizeAttributeName(attrName)

  // Check if forbidden (event handlers, formaction, etc.)
  if (isForbiddenAttribute(normalized, options.forbiddenAttributes)) {
    return {
      allowed: false,
      attrName: normalized,
      attrValue,
      // BUG-7 fix: isEventHandler() checks FORBIDDEN_ATTRIBUTES first, so non-event-handler
      // forbidden attributes like `formaction` incorrectly get "Event handler attribute" reason.
      // Use EVENT_HANDLER_REGEX directly to distinguish true event handlers from other forbidden attrs.
      reason: EVENT_HANDLER_REGEX.test(normalized)
        ? `Event handler attribute: ${normalized}`
        : `Forbidden attribute: ${normalized}`,
    }
  }

  // Check if allowed for this tag
  if (!isAttributeAllowed(tagName, normalized, allowedAttributes, options)) {
    return {
      allowed: false,
      attrName: normalized,
      attrValue,
      reason: `Attribute not allowed for tag <${tagName}>: ${normalized}`,
    }
  }

  // Check for DOM clobbering (id/name attributes that shadow DOM APIs)
  // preventDOMClobbering=true means we prevent it (allowDomClobbering=false)
  // preventDOMClobbering=false (default) means we allow it (allowDomClobbering=true)
  const domClobberingResult = validateDomClobbering(
    tagName,
    normalized,
    attrValue,
    !(options.preventDOMClobbering ?? false)  // Invert: prevent=true → allow=false
  )

  if (!domClobberingResult.allowed) {
    return {
      allowed: false,
      attrName: normalized,
      attrValue,
      reason: domClobberingResult.reason ?? 'DOM clobbering detected',
    }
  }

  // Validate URL protocols for URL attributes
  if (isURLAttribute(normalized)) {
    const urlSafe = isSafeURL(attrValue, options.allowedProtocols)

    if (!urlSafe) {
      return {
        allowed: false,
        attrName: normalized,
        attrValue,
        reason: `Dangerous URL protocol in attribute ${normalized}`,
      }
    }

    // Sanitize URL (remove dangerous protocols)
    const sanitized = sanitizeURL(attrValue, options.allowedProtocols, '')

    if (sanitized !== attrValue) {
      return {
        allowed: true,
        attrName: normalized,
        attrValue,
        sanitizedValue: sanitized,
      }
    }
  }

  // Validate style attribute (CSS injection prevention)
  if (normalized === 'style') {
    const styleValidation = validateStyleAttribute(attrValue, {
      allowStyleAttribute: options.allowStyleAttribute ?? false,
      strictCSSValidation: options.strictCSSValidation ?? false,
    })

    if (!styleValidation.allowed) {
      return {
        allowed: false,
        attrName: normalized,
        attrValue,
        reason: styleValidation.reason ?? 'Dangerous CSS detected',
      }
    }

    // Return sanitized CSS if it was modified
    if (styleValidation.sanitizedValue && styleValidation.sanitizedValue !== attrValue) {
      return {
        allowed: true,
        attrName: normalized,
        attrValue,
        sanitizedValue: styleValidation.sanitizedValue,
      }
    }
  }

  // Attribute is allowed
  return {
    allowed: true,
    attrName: normalized,
    attrValue,
  }
}

/**
 * Filter allowed attributes for an element
 *
 * Returns only attributes that are allowed for the given tag.
 *
 * @param tagName - Tag name (lowercase)
 * @param attributes - Map of attribute name → value
 * @param allowedAttributes - Allowed attributes per tag
 * @param options - Sanitization options
 * @returns Map of allowed attribute name → value
 *
 * @example
 * filterAllowedAttributes('a', { href: 'https://example.com', onclick: 'alert(1)' })
 * // { href: 'https://example.com' }
 */
export function filterAllowedAttributes(
  tagName: string,
  attributes: Record<string, string>,
  allowedAttributes: Readonly<Record<string, readonly string[]>> | Record<string, string[]> = DEFAULT_ALLOWED_ATTRIBUTES,
  options: Partial<SanitizeOptions> = {}
): Record<string, string> {
  const result: Record<string, string> = {}

  for (const [attrName, attrValue] of Object.entries(attributes)) {
    const validation = validateAttribute(tagName, attrName, attrValue, allowedAttributes, options)

    if (validation.allowed) {
      // Use sanitized value if available
      result[validation.attrName] = validation.sanitizedValue ?? validation.attrValue
    }
  }

  return result
}
