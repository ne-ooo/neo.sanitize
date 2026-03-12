/**
 * @lpm.dev/neo.sanitize - TypeScript type definitions
 *
 * Comprehensive type system for HTML sanitization configuration and results.
 */

/**
 * Configuration options for HTML sanitization
 */
export interface SanitizeOptions {
  /**
   * List of allowed HTML tags
   * @default DEFAULT_ALLOWED_TAGS
   * @example ['p', 'br', 'strong', 'em']
   */
  allowedTags?: string[]

  /**
   * List of allowed attributes per tag
   * @default DEFAULT_ALLOWED_ATTRIBUTES
   * @example { a: ['href', 'title'], img: ['src', 'alt'] }
   */
  allowedAttributes?: Record<string, string[]>

  /**
   * List of allowed URL protocols for href, src, etc.
   * @default ['http', 'https', 'mailto', 'tel']
   * @example ['http', 'https', 'ftp']
   */
  allowedProtocols?: string[]

  /**
   * List of forbidden attributes (always removed)
   * @default FORBIDDEN_ATTRIBUTES (event handlers like onclick, onerror)
   * @example ['onclick', 'onerror', 'onload']
   */
  forbiddenAttributes?: string[]

  /**
   * Allow all attributes for specified tags
   * @default []
   * @example ['code', 'pre'] // Allow all attributes on code/pre tags
   */
  allowAllAttributes?: string[]

  /**
   * Allow data-* attributes globally
   * @default false
   */
  allowDataAttributes?: boolean

  /**
   * Allow aria-* attributes globally (for accessibility)
   * @default true
   */
  allowAriaAttributes?: boolean

  /**
   * Allow class attribute globally
   * @default false
   */
  allowClassAttribute?: boolean

  /**
   * Allow id attribute globally
   * @default false
   */
  allowIdAttribute?: boolean

  /**
   * Allow style attribute globally (WARNING: CSS injection risk)
   * @default false
   */
  allowStyleAttribute?: boolean

  /**
   * Strip tags instead of removing them entirely
   * If true, <script>alert('xss')</script> becomes alert('xss')
   * @default false
   */
  stripTags?: boolean

  /**
   * Keep text content when removing dangerous tags
   * @default true
   */
  keepTextContent?: boolean

  /**
   * Transform tag names to lowercase
   * @default true
   */
  lowercaseTags?: boolean

  /**
   * Transform attribute names to lowercase
   * @default true
   */
  lowercaseAttributes?: boolean

  /**
   * Return sanitized HTML as string
   * If false, returns DocumentFragment
   * @default true
   */
  returnString?: boolean

  /**
   * Enable DOM clobbering prevention (Phase 2)
   * @default false
   */
  preventDOMClobbering?: boolean

  /**
   * Enable mXSS detection (Phase 2)
   * @default false
   */
  detectMXSS?: boolean

  /**
   * Enable strict CSS validation (Phase 2)
   * Only allows whitelisted CSS properties when true
   * @default false
   */
  strictCSSValidation?: boolean

  /**
   * Hooks for customizing sanitization behavior (Phase 2)
   * @default undefined
   */
  hooks?: SanitizeHooks
}

/**
 * Predefined sanitization schema
 */
export type SanitizeSchema = 'BASIC' | 'RELAXED' | 'STRICT'

/**
 * Result of sanitization operation
 */
export interface SanitizeResult {
  /**
   * Sanitized HTML string or DocumentFragment
   */
  html: string | DocumentFragment

  /**
   * Number of tags removed
   */
  removedTags?: number

  /**
   * Number of attributes removed
   */
  removedAttributes?: number

  /**
   * List of removed tag names
   */
  removedTagNames?: string[]

  /**
   * List of removed attribute names
   */
  removedAttributeNames?: string[]

  /**
   * Whether any modifications were made
   */
  modified: boolean
}

/**
 * Sanitizer instance (for reusable configuration)
 */
export interface Sanitizer {
  /**
   * Sanitize HTML string with preconfigured options
   */
  sanitize(html: string): string | DocumentFragment

  /**
   * Get current configuration
   */
  getConfig(): Readonly<Required<Omit<SanitizeOptions, 'hooks'>>>

  /**
   * Update configuration
   */
  updateConfig(options: Partial<SanitizeOptions>): void
}

/**
 * Hook functions for customizing sanitization behavior (Phase 2)
 */
export interface SanitizeHooks {
  /**
   * Called before sanitization starts
   */
  beforeSanitize?: (html: string) => string | void

  /**
   * Called for each element during sanitization
   * Return false to remove element
   */
  onElement?: (element: Element) => boolean | void

  /**
   * Called for each attribute during validation
   * Return false to remove attribute
   */
  onAttribute?: (element: Element, attrName: string, attrValue: string) => boolean | void

  /**
   * Called after sanitization completes
   */
  afterSanitize?: (result: DocumentFragment) => DocumentFragment | void
}

/**
 * Extended sanitization options with hooks (Phase 2)
 */
export interface SanitizeOptionsWithHooks extends SanitizeOptions {
  hooks?: SanitizeHooks
}

/**
 * Protocol validation result
 */
export interface ProtocolValidationResult {
  /**
   * Whether the protocol is allowed
   */
  allowed: boolean

  /**
   * The protocol name (e.g., 'http', 'javascript')
   */
  protocol: string | null

  /**
   * Whether the URL is dangerous
   */
  dangerous: boolean

  /**
   * Reason for rejection (if not allowed)
   */
  reason?: string
}

/**
 * Tag validation result
 */
export interface TagValidationResult {
  /**
   * Whether the tag is allowed
   */
  allowed: boolean

  /**
   * The tag name (lowercase)
   */
  tagName: string

  /**
   * Reason for rejection (if not allowed)
   */
  reason?: string
}

/**
 * Attribute validation result
 */
export interface AttributeValidationResult {
  /**
   * Whether the attribute is allowed
   */
  allowed: boolean

  /**
   * The attribute name (lowercase)
   */
  attrName: string

  /**
   * The attribute value
   */
  attrValue: string

  /**
   * Reason for rejection (if not allowed)
   */
  reason?: string

  /**
   * Sanitized attribute value (if modified)
   */
  sanitizedValue?: string
}
