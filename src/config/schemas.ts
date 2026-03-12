/**
 * @lpm.dev/neo.sanitize - Predefined Schemas
 *
 * Predefined sanitization configurations for different use cases:
 * - BASIC: Minimal HTML (text formatting only)
 * - RELAXED: Rich HTML (images, links, tables, formatting)
 * - STRICT: Paranoid security (text only, no HTML)
 */

import type { SanitizeOptions } from '../types.js'
import { DEFAULT_OPTIONS } from './defaults.js'

/**
 * BASIC schema - Minimal HTML (text formatting only)
 *
 * Use cases:
 * - User comments (simple formatting)
 * - Text messages with basic formatting
 * - Email signatures
 *
 * Allowed:
 * - Text formatting: p, br, strong, em, u, code, pre
 * - Lists: ul, ol, li
 * - Links: a (href only)
 * - No images, no tables, no classes/ids
 *
 * Security level: HIGH
 * Usability: LOW (very limited HTML)
 */
export const BASIC_SCHEMA: Required<Omit<SanitizeOptions, 'hooks'>> = {
  ...DEFAULT_OPTIONS,

  // Minimal tags (text formatting only)
  allowedTags: [
    // Text formatting
    'p',
    'br',
    'span',
    'strong',
    'b',
    'em',
    'i',
    'u',
    's',
    'del',
    'code',
    'pre',

    // Lists
    'ul',
    'ol',
    'li',

    // Links
    'a',
  ],

  // Minimal attributes
  allowedAttributes: {
    a: ['href', 'title'], // Links with href only
  },

  // Only http/https protocols
  allowedProtocols: ['http', 'https'],

  // No data-* attributes
  allowDataAttributes: false,

  // No class/id attributes
  allowClassAttribute: false,
  allowIdAttribute: false,

  // No style attribute
  allowStyleAttribute: false,
}

/**
 * RELAXED schema - Rich HTML (images, links, tables, formatting)
 *
 * Use cases:
 * - Blog posts
 * - Rich text editors
 * - Documentation
 * - User-generated content with formatting
 *
 * Allowed:
 * - All text formatting
 * - Images (with src, alt)
 * - Links (with href, title, rel, target)
 * - Tables (full table markup)
 * - Headings (h1-h6)
 * - Blockquotes, code blocks
 * - Class attributes (for syntax highlighting)
 *
 * Security level: MEDIUM
 * Usability: HIGH (rich HTML editing)
 */
export const RELAXED_SCHEMA: Required<Omit<SanitizeOptions, 'hooks'>> = {
  ...DEFAULT_OPTIONS,

  // All default tags (including images, tables, headings)
  allowedTags: [...DEFAULT_OPTIONS.allowedTags],

  // All default attributes (including images, links, tables)
  allowedAttributes: { ...DEFAULT_OPTIONS.allowedAttributes },

  // All safe protocols
  allowedProtocols: ['http', 'https', 'mailto', 'tel', 'ftp', 'ftps'],

  // Allow class for syntax highlighting
  allowClassAttribute: true,

  // Allow data-* for rich interactions
  allowDataAttributes: true,

  // Still no id (DOM clobbering risk)
  allowIdAttribute: false,

  // Still no style (CSS injection risk)
  allowStyleAttribute: false,

  // Allow all attributes on code/pre for syntax highlighting
  allowAllAttributes: ['code', 'pre'],
}

/**
 * STRICT schema - Paranoid security (text only, no HTML)
 *
 * Use cases:
 * - Untrusted user input
 * - High-security applications
 * - Text-only content (strip all HTML)
 *
 * Allowed:
 * - No HTML tags (all stripped)
 * - Only plain text
 * - All dangerous content removed
 *
 * Security level: MAXIMUM
 * Usability: NONE (all HTML stripped)
 */
export const STRICT_SCHEMA: Required<Omit<SanitizeOptions, 'hooks'>> = {
  ...DEFAULT_OPTIONS,

  // No tags allowed (strip all HTML)
  allowedTags: [],

  // No attributes allowed
  allowedAttributes: {},

  // No protocols needed (no URLs)
  allowedProtocols: [],

  // Strip tags and keep text content
  stripTags: true,
  keepTextContent: true,

  // No special attributes
  allowDataAttributes: false,
  allowAriaAttributes: false,
  allowClassAttribute: false,
  allowIdAttribute: false,
  allowStyleAttribute: false,
}

/**
 * Get schema by name
 *
 * @param schemaName - Schema name ('BASIC', 'RELAXED', 'STRICT')
 * @returns Schema configuration
 *
 * @example
 * const schema = getSchema('BASIC')
 * const html = sanitize('<p>Hello <script>alert(1)</script></p>', schema)
 * // '<p>Hello </p>'
 */
export function getSchema(schemaName: 'BASIC' | 'RELAXED' | 'STRICT'): Required<Omit<SanitizeOptions, 'hooks'>> {
  switch (schemaName) {
    case 'BASIC':
      return BASIC_SCHEMA
    case 'RELAXED':
      return RELAXED_SCHEMA
    case 'STRICT':
      return STRICT_SCHEMA
    default:
      return DEFAULT_OPTIONS
  }
}

/**
 * Merge schema with custom options
 *
 * Allows overriding specific options while using a schema as base.
 *
 * @param schemaName - Schema name
 * @param customOptions - Custom options to override
 * @returns Merged configuration
 *
 * @example
 * const schema = mergeSchema('BASIC', { allowDataAttributes: true })
 * // BASIC schema + data-* attributes allowed
 */
export function mergeSchema(
  schemaName: 'BASIC' | 'RELAXED' | 'STRICT',
  customOptions: Partial<SanitizeOptions>
): Required<Omit<SanitizeOptions, 'hooks'>> {
  const schema = getSchema(schemaName)

  return {
    ...schema,
    ...customOptions,
    // Merge arrays
    allowedTags: customOptions.allowedTags ?? schema.allowedTags,
    allowedAttributes: customOptions.allowedAttributes ?? schema.allowedAttributes,
    allowedProtocols: customOptions.allowedProtocols ?? schema.allowedProtocols,
    forbiddenAttributes: customOptions.forbiddenAttributes ?? schema.forbiddenAttributes,
    allowAllAttributes: customOptions.allowAllAttributes ?? schema.allowAllAttributes,
  }
}
