/**
 * @lpm.dev/neo.sanitize - Predefined Schemas
 *
 * Predefined sanitization configurations for different use cases:
 * - BASIC: Minimal HTML (text formatting only)
 * - RELAXED: Rich HTML (images, links, tables, formatting)
 * - STRICT: Paranoid security (text only, no HTML)
 */

import type { ResolvedSanitizeOptions, SanitizeOptions } from '../types.js'
import { DEFAULT_OPTIONS } from './defaults.js'
import { mergeOptions, readOwnOption } from './options.js'
import { deepFreeze } from '../utils/object.js'

type MergedSanitizeSchema = Required<Omit<SanitizeOptions, 'hooks'>> &
  Pick<SanitizeOptions, 'hooks'>

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
export const BASIC_SCHEMA: ResolvedSanitizeOptions = deepFreeze({
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
})

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
export const RELAXED_SCHEMA: ResolvedSanitizeOptions = deepFreeze({
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

  // class is already allowed explicitly on code/pre by the default attribute
  // policy. Do not admit id/name through a broad attribute bypass.
  allowAllAttributes: [],
})

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
export const STRICT_SCHEMA: ResolvedSanitizeOptions = deepFreeze({
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
})

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
export function getSchema(
  schemaName: 'BASIC' | 'RELAXED' | 'STRICT'
): ResolvedSanitizeOptions {
  switch (schemaName) {
    case 'BASIC':
      return BASIC_SCHEMA
    case 'RELAXED':
      return RELAXED_SCHEMA
    case 'STRICT':
      return STRICT_SCHEMA
    default:
      throw new RangeError(
        `@lpm.dev/neo.sanitize: Unknown schema "${String(schemaName)}". ` +
          'Expected BASIC, RELAXED, or STRICT.'
      )
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
): MergedSanitizeSchema {
  const schema = getSchema(schemaName)
  const merged: MergedSanitizeSchema = mergeOptions(schema, customOptions)
  const hooks = readOwnOption(customOptions, 'hooks')
  if (hooks !== undefined) merged.hooks = hooks

  return merged
}
