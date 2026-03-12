/**
 * @lpm.dev/neo.sanitize - CSS Injection Prevention
 *
 * Validates and sanitizes CSS to prevent:
 * - CSS expression() attacks (IE)
 * - @import attacks (external CSS loading)
 * - url() with dangerous protocols
 * - behavior: property (IE XBL)
 * - -moz-binding (Firefox XBL)
 * - CSS animations with JavaScript
 *
 * References:
 * - https://owasp.org/www-community/attacks/CSS_Injection
 * - https://portswigger.net/web-security/cross-site-scripting/contexts#xss-in-html-tag-attributes
 */

/**
 * Dangerous CSS patterns that invalidate entire CSS string
 *
 * These patterns make the entire CSS dangerous and should remove everything.
 */
export const GLOBAL_DANGEROUS_PATTERNS: readonly RegExp[] = [
  // CSS expression() - IE only, but still dangerous
  /expression\s*\(/i,

  // @import - can load external malicious CSS
  /@import/i,
]

/**
 * Dangerous CSS patterns in property values
 *
 * These are checked per-property and just that property is removed.
 */
export const VALUE_DANGEROUS_PATTERNS: readonly RegExp[] = [
  // javascript: protocol in url()
  /url\s*\(\s*['"]*javascript:/i,

  // data: protocol in url() (can contain scripts)
  /url\s*\(\s*['"]*data:/i,

  // vbscript: protocol
  /url\s*\(\s*['"]*vbscript:/i,

  // expression() in values
  /expression\s*\(/i,
]

/**
 * Dangerous CSS properties that should be blocked
 */
export const FORBIDDEN_CSS_PROPERTIES: readonly string[] = [
  'behavior',        // IE HTC files
  '-moz-binding',    // Firefox XBL
  'binding',         // Generic binding
]

/**
 * Safe CSS properties whitelist (for strict mode)
 *
 * If provided, ONLY these properties are allowed.
 * Most applications don't need this level of restriction.
 */
export const SAFE_CSS_PROPERTIES: readonly string[] = [
  // Layout
  'display',
  'position',
  'top',
  'right',
  'bottom',
  'left',
  'float',
  'clear',
  'overflow',
  'overflow-x',
  'overflow-y',
  'clip',
  'zoom',

  // Box model
  'width',
  'min-width',
  'max-width',
  'height',
  'min-height',
  'max-height',
  'margin',
  'margin-top',
  'margin-right',
  'margin-bottom',
  'margin-left',
  'padding',
  'padding-top',
  'padding-right',
  'padding-bottom',
  'padding-left',

  // Border
  'border',
  'border-width',
  'border-style',
  'border-color',
  'border-radius',
  'border-top',
  'border-right',
  'border-bottom',
  'border-left',

  // Background
  'background',
  'background-color',
  'background-image',
  'background-repeat',
  'background-position',
  'background-size',

  // Text
  'color',
  'font',
  'font-family',
  'font-size',
  'font-weight',
  'font-style',
  'font-variant',
  'line-height',
  'text-align',
  'text-decoration',
  'text-indent',
  'text-transform',
  'text-shadow',
  'letter-spacing',
  'word-spacing',
  'white-space',

  // Flexbox
  'flex',
  'flex-direction',
  'flex-wrap',
  'flex-flow',
  'justify-content',
  'align-items',
  'align-content',
  'order',
  'flex-grow',
  'flex-shrink',
  'flex-basis',

  // Grid
  'grid',
  'grid-template',
  'grid-template-columns',
  'grid-template-rows',
  'grid-gap',
  'gap',

  // Transform
  'transform',
  'transform-origin',

  // Transition
  'transition',
  'transition-property',
  'transition-duration',
  'transition-timing-function',
  'transition-delay',

  // Animation (safe if content is validated)
  'animation',
  'animation-name',
  'animation-duration',
  'animation-timing-function',
  'animation-delay',
  'animation-iteration-count',
  'animation-direction',
  'animation-fill-mode',

  // Other
  'opacity',
  'visibility',
  'z-index',
  'cursor',
  'list-style',
  'outline',
  'box-shadow',
  'vertical-align',
]

/**
 * Check if CSS contains globally dangerous patterns
 *
 * These patterns invalidate the entire CSS string.
 *
 * @param css - CSS string to validate
 * @returns Validation result with details
 *
 * @example
 * hasGloballyDangerousCSS('@import url(evil.css)')  // { dangerous: true }
 * hasGloballyDangerousCSS('color: red')  // { dangerous: false }
 */
export function hasGloballyDangerousCSS(
  css: string
): { dangerous: boolean; reason?: string; pattern?: RegExp } {
  if (!css || typeof css !== 'string') {
    return { dangerous: false }
  }

  // Check against globally dangerous patterns
  for (const pattern of GLOBAL_DANGEROUS_PATTERNS) {
    if (pattern.test(css)) {
      return {
        dangerous: true,
        reason: `Dangerous CSS pattern detected: ${pattern.source}`,
        pattern,
      }
    }
  }

  return { dangerous: false }
}

/**
 * Check if CSS value contains dangerous patterns
 *
 * Used for per-property validation.
 *
 * @param cssValue - CSS value to validate
 * @returns Validation result with details
 *
 * @example
 * hasDangerousValue('url(javascript:alert(1))')  // { dangerous: true }
 * hasDangerousValue('red')  // { dangerous: false }
 */
export function hasDangerousValue(
  cssValue: string
): { dangerous: boolean; reason?: string; pattern?: RegExp } {
  if (!cssValue || typeof cssValue !== 'string') {
    return { dangerous: false }
  }

  // Check against value dangerous patterns
  for (const pattern of VALUE_DANGEROUS_PATTERNS) {
    if (pattern.test(cssValue)) {
      return {
        dangerous: true,
        reason: `Dangerous CSS value pattern detected: ${pattern.source}`,
        pattern,
      }
    }
  }

  return { dangerous: false }
}

/**
 * Check if CSS contains dangerous patterns (legacy function)
 *
 * Checks both global and value patterns.
 *
 * @param css - CSS string to validate
 * @returns Validation result with details
 *
 * @example
 * hasDangerousCSS('color: red')  // { dangerous: false }
 * hasDangerousCSS('background: url(javascript:alert(1))')  // { dangerous: true }
 * hasDangerousCSS('width: expression(alert(1))')  // { dangerous: true }
 */
export function hasDangerousCSS(
  css: string
): { dangerous: boolean; reason?: string; pattern?: RegExp } {
  // Check globally dangerous patterns first
  const globalCheck = hasGloballyDangerousCSS(css)
  if (globalCheck.dangerous) {
    return globalCheck
  }

  // Check value patterns
  return hasDangerousValue(css)
}

/**
 * Check if a CSS property is forbidden
 *
 * @param property - CSS property name
 * @returns true if property is forbidden
 *
 * @example
 * isForbiddenCSSProperty('behavior')  // true
 * isForbiddenCSSProperty('-moz-binding')  // true
 * isForbiddenCSSProperty('color')  // false
 */
export function isForbiddenCSSProperty(property: string): boolean {
  if (!property || typeof property !== 'string') {
    return false
  }

  const normalized = property.toLowerCase().trim()
  return FORBIDDEN_CSS_PROPERTIES.includes(normalized)
}

/**
 * Check if a CSS property is in the safe whitelist
 *
 * @param property - CSS property name
 * @returns true if property is in safe whitelist
 *
 * @example
 * isSafeCSSProperty('color')  // true
 * isSafeCSSProperty('width')  // true
 * isSafeCSSProperty('behavior')  // false
 */
export function isSafeCSSProperty(property: string): boolean {
  if (!property || typeof property !== 'string') {
    return false
  }

  const normalized = property.toLowerCase().trim()
  return SAFE_CSS_PROPERTIES.includes(normalized)
}

/**
 * Sanitize CSS string by removing dangerous patterns
 *
 * @param css - CSS string to sanitize
 * @param strictMode - If true, only allow whitelisted properties
 * @returns Sanitized CSS string
 *
 * @example
 * sanitizeCSS('color: red')  // 'color: red'
 * sanitizeCSS('color: red; behavior: url(xss.htc)')  // 'color: red'
 * sanitizeCSS('width: expression(alert(1))')  // ''
 */
export function sanitizeCSS(css: string, strictMode: boolean = false): string {
  if (!css || typeof css !== 'string') {
    return ''
  }

  // Check for globally dangerous patterns first (expression, @import)
  // These invalidate the entire CSS string
  const globalCheck = hasGloballyDangerousCSS(css)
  if (globalCheck.dangerous) {
    // Remove entire style if globally dangerous pattern found
    return ''
  }

  // In strict mode, validate each property
  if (strictMode) {
    // Parse CSS declarations (simple parser)
    const declarations = css.split(';').map(d => d.trim()).filter(Boolean)
    const safeDeclara = []

    for (const declaration of declarations) {
      const colonIndex = declaration.indexOf(':')
      if (colonIndex === -1) continue

      const property = declaration.slice(0, colonIndex).trim()
      const value = declaration.slice(colonIndex + 1).trim()

      // Check if property is safe
      if (isSafeCSSProperty(property) && !isForbiddenCSSProperty(property)) {
        // Check if value is safe
        if (!hasDangerousValue(value).dangerous) {
          safeDeclara.push(`${property}: ${value}`)
        }
      }
    }

    return safeDeclara.join('; ')
  }

  // Non-strict mode: just remove forbidden properties
  const declarations = css.split(';').map(d => d.trim()).filter(Boolean)
  const safeDeclara = []

  for (const declaration of declarations) {
    const colonIndex = declaration.indexOf(':')
    if (colonIndex === -1) continue

    const property = declaration.slice(0, colonIndex).trim()
    const value = declaration.slice(colonIndex + 1).trim()

    // Skip forbidden properties
    if (isForbiddenCSSProperty(property)) continue

    // Skip if value has dangerous patterns
    if (hasDangerousValue(value).dangerous) continue

    safeDeclara.push(declaration)
  }

  return safeDeclara.join('; ')
}

/**
 * Validate style attribute value
 *
 * Comprehensive validation of inline styles.
 *
 * @param styleValue - Style attribute value (inline CSS)
 * @param options - Validation options
 * @returns Validation result
 *
 * @example
 * validateStyleAttribute('color: red')
 * // { allowed: true, sanitizedValue: 'color: red' }
 *
 * validateStyleAttribute('width: expression(alert(1))')
 * // { allowed: false, reason: 'Dangerous CSS pattern detected' }
 */
export function validateStyleAttribute(
  styleValue: string,
  options: {
    allowStyleAttribute?: boolean
    strictCSSValidation?: boolean
  } = {}
): {
  allowed: boolean
  sanitizedValue?: string
  reason?: string
} {
  // If style attribute is not allowed, reject
  if (!options.allowStyleAttribute) {
    return {
      allowed: false,
      reason: 'Style attribute not allowed',
    }
  }

  // Check for globally dangerous CSS patterns (expression, @import)
  const globalCheck = hasGloballyDangerousCSS(styleValue)
  if (globalCheck.dangerous) {
    return {
      allowed: false,
      reason: globalCheck.reason ?? 'Dangerous CSS pattern detected',
    }
  }

  // Sanitize CSS
  const sanitized = sanitizeCSS(styleValue, options.strictCSSValidation ?? false)

  if (!sanitized || sanitized.trim() === '') {
    return {
      allowed: false,
      reason: 'All CSS properties were removed during sanitization',
    }
  }

  return {
    allowed: true,
    sanitizedValue: sanitized,
  }
}
