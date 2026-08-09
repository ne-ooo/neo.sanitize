/**
 * @lpm.dev/neo.sanitize - Default Configuration
 *
 * Default sanitization options for general use.
 * Provides a safe baseline that blocks most XSS vectors.
 */

import type { SanitizeOptions } from '../types.js'
import { deepFreeze } from '../utils/object.js'
import {
  DEFAULT_ALLOWED_TAGS,
  DEFAULT_ALLOWED_ATTRIBUTES,
  ALLOWED_PROTOCOLS,
  FORBIDDEN_ATTRIBUTES,
} from '../utils/constants.js'

/**
 * Default sanitization options
 *
 * Safe defaults for general HTML sanitization:
 * - Allows common formatting tags (p, div, strong, etc.)
 * - Allows safe attributes (href, src, alt, etc.)
 * - Allows safe protocols (http, https, mailto, tel)
 * - Forbids all event handlers (onclick, onerror, etc.)
 * - Allows ARIA attributes for accessibility
 * - Denies data-* attributes by default (privacy)
 * - Denies id/class attributes by default (CSS collision)
 * - Denies style attribute by default (CSS injection)
 */
export const DEFAULT_OPTIONS: Required<Omit<SanitizeOptions, 'hooks'>> = deepFreeze({
  // Tags and attributes
  allowedTags: [...DEFAULT_ALLOWED_TAGS],
  allowedAttributes: Object.fromEntries(
    Object.entries(DEFAULT_ALLOWED_ATTRIBUTES).map(([key, val]) => [key, [...val]])
  ) as Record<string, string[]>,
  allowedProtocols: [...ALLOWED_PROTOCOLS],
  forbiddenAttributes: [...FORBIDDEN_ATTRIBUTES],

  // Global attributes
  allowAllAttributes: [],
  allowDataAttributes: false, // Privacy: data-* can be used for tracking
  allowAriaAttributes: true, // Accessibility: allow aria-* by default
  allowClassAttribute: false, // Security: class can cause CSS collisions
  allowIdAttribute: false, // Security: id can cause DOM clobbering
  allowStyleAttribute: false, // Security: style can have CSS injection

  // Behavior
  stripTags: false, // Keep wrappers for allowed elements
  keepTextContent: true, // Unwrap denied safe elements and keep sanitized children
  lowercaseTags: true, // Normalize tag names to lowercase
  lowercaseAttributes: true, // Normalize attribute names to lowercase
  returnString: true, // Return sanitized HTML as string (not DocumentFragment)

  // Advanced security (Phase 2)
  preventDOMClobbering: false, // Phase 2 feature
  detectMXSS: false, // Experimental feature
  strictCSSValidation: false, // Phase 2 feature
})
