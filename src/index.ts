/**
 * @lpm.dev/neo.sanitize - Main Entry Point
 *
 * Zero-dependency HTML sanitization for browsers and Node.js.
 * Prevents XSS attacks while allowing safe HTML formatting.
 *
 * @example
 * import { sanitize } from '@lpm.dev/neo.sanitize'
 *
 * // Basic usage
 * const safe = sanitize('<p>Hello <script>alert(1)</script></p>')
 * // '<p>Hello </p>'
 *
 * // With options
 * const safe2 = sanitize('<p class="text">Hello</p>', {
 *   allowClassAttribute: true
 * })
 * // '<p class="text">Hello</p>'
 *
 * // With schema
 * import { BASIC_SCHEMA, RELAXED_SCHEMA, STRICT_SCHEMA } from '@lpm.dev/neo.sanitize'
 * const safe3 = sanitize(html, BASIC_SCHEMA)
 */

// Main sanitization functions
export { sanitize, createSanitizer, sanitizeBasic, sanitizeRelaxed, sanitizeStrict } from './core/sanitizer.js'

// Parser functions
export { parseHTML, serializeHTML, isBrowser, isNode } from './core/parser.js'

// Validators
export {
  // Protocol validators
  getProtocol,
  isProtocolAllowed,
  isDangerousProtocol,
  validateProtocol,
  sanitizeURL,
  isSafeURL,
} from './validators/protocols.js'

export {
  // Tag validators
  normalizeTagName,
  isTagAllowed,
  isDangerousTag,
  validateTag,
  filterAllowedTags,
  getDangerousTags,
  DANGEROUS_TAGS,
} from './validators/tags.js'

export {
  // Attribute validators
  normalizeAttributeName,
  isEventHandler,
  isDataAttribute,
  isAriaAttribute,
  isURLAttribute,
  isForbiddenAttribute,
  isAttributeAllowed,
  validateAttribute,
  filterAllowedAttributes,
} from './validators/attributes.js'

// Configuration
export { DEFAULT_OPTIONS } from './config/defaults.js'
export { BASIC_SCHEMA, RELAXED_SCHEMA, STRICT_SCHEMA, getSchema, mergeSchema } from './config/schemas.js'

// Constants
export {
  DEFAULT_ALLOWED_TAGS,
  DEFAULT_ALLOWED_ATTRIBUTES,
  ALLOWED_PROTOCOLS,
  DANGEROUS_PROTOCOLS,
  FORBIDDEN_ATTRIBUTES,
  VOID_ELEMENTS,
  URL_ATTRIBUTES,
  EVENT_HANDLER_REGEX,
  DATA_ATTRIBUTE_REGEX,
  ARIA_ATTRIBUTE_REGEX,
} from './utils/constants.js'

// TypeScript types
export type {
  SanitizeOptions,
  SanitizeSchema,
  SanitizeResult,
  Sanitizer,
  SanitizeHooks,
  SanitizeOptionsWithHooks,
  ProtocolValidationResult,
  TagValidationResult,
  AttributeValidationResult,
} from './types.js'
