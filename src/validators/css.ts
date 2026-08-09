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

import { isSafeURL } from './protocols.js'
import { deepFreeze } from '../utils/object.js'

/**
 * Dangerous CSS properties that should be blocked
 */
export const FORBIDDEN_CSS_PROPERTIES: readonly string[] = deepFreeze([
  'behavior',        // IE HTC files
  '-moz-binding',    // Firefox XBL
  'binding',         // Generic binding
])

/**
 * Safe CSS properties whitelist (for strict mode)
 *
 * If provided, ONLY these properties are allowed.
 * Most applications don't need this level of restriction.
 */
export const SAFE_CSS_PROPERTIES: readonly string[] = deepFreeze([
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
])

interface CSSDeclaration {
  property: string
  value: string
}

interface CSSFunctionToken {
  name: string
  argument: string
}

interface CSSCheckResult {
  dangerous: boolean
  reason?: string
}

const CSS_URL_PROTOCOLS: readonly string[] = ['http', 'https']
const MAX_CSS_NESTING = 64
const MAX_CSS_FUNCTIONS = 256
const INVALID_FUNCTION_TOKEN = '__invalid_css__'
const STRICT_DYNAMIC_FUNCTIONS: readonly string[] = ['var', 'env', 'attr']
const RESOURCE_FUNCTIONS: readonly string[] = [
  'image',
  'image-set',
  '-webkit-image-set',
  'cross-fade',
  'element',
  'paint',
]
const FORBIDDEN_CSS_PROPERTY_SET = new Set(FORBIDDEN_CSS_PROPERTIES)
const SAFE_CSS_PROPERTY_SET = new Set(SAFE_CSS_PROPERTIES)
const STRICT_DYNAMIC_FUNCTION_SET = new Set(STRICT_DYNAMIC_FUNCTIONS)
const RESOURCE_FUNCTION_SET = new Set(RESOURCE_FUNCTIONS)

function isHexDigit(character: string): boolean {
  const code = character.charCodeAt(0)
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 70) ||
    (code >= 97 && code <= 102)
  )
}

function isWhitespace(character: string): boolean {
  return character === ' ' || character === '\t' || character === '\n' || character === '\f' || character === '\r'
}

function consumeEscape(input: string, start: number): { value: string; next: number } {
  const first = input[start + 1]
  if (first === undefined) return { value: '', next: input.length }

  // A backslash followed by a newline is a CSS line continuation.
  if (first === '\n' || first === '\f' || first === '\r') {
    const next = first === '\r' && input[start + 2] === '\n' ? start + 3 : start + 2
    return { value: '', next }
  }

  if (!isHexDigit(first)) {
    return { value: first, next: start + 2 }
  }

  let end = start + 1
  while (end < input.length && end < start + 7 && isHexDigit(input[end] ?? '')) {
    end++
  }

  const codePoint = Number.parseInt(input.slice(start + 1, end), 16)
  if (isWhitespace(input[end] ?? '')) end++

  const validCodePoint = codePoint !== 0 && codePoint <= 0x10ffff && !(codePoint >= 0xd800 && codePoint <= 0xdfff)
  return {
    value: validCodePoint ? String.fromCodePoint(codePoint) : '\uFFFD',
    next: end,
  }
}

/** Decode CSS escapes and remove comments before security analysis. */
function canonicalizeCSS(input: string): { value: string; valid: boolean } {
  let output = ''
  let index = 0

  while (index < input.length) {
    const character = input[index] ?? ''

    if (character === '/' && input[index + 1] === '*') {
      const commentEnd = input.indexOf('*/', index + 2)
      if (commentEnd === -1) return { value: output, valid: false }
      index = commentEnd + 2
      continue
    }

    if (character === '\\') {
      if (index + 1 >= input.length) return { value: output, valid: false }
      const escape = consumeEscape(input, index)
      output += escape.value
      index = escape.next
      continue
    }

    output += character
    index++
  }

  return { value: output, valid: true }
}

function skipRawEscape(input: string, start: number): number {
  return consumeEscape(input, start).next
}

/** Split declarations without treating quoted or parenthesized semicolons as separators. */
function splitCSSDeclarations(css: string): CSSDeclaration[] | null {
  const segments: string[] = []
  let segmentStart = 0
  let quote: '"' | "'" | null = null
  let depth = 0

  for (let index = 0; index < css.length; index++) {
    const character = css[index] ?? ''

    if (character === '\\') {
      if (index + 1 >= css.length) return null
      index = skipRawEscape(css, index) - 1
      continue
    }

    if (quote) {
      if (character === quote) quote = null
      continue
    }

    if (character === '"' || character === "'") {
      quote = character
      continue
    }

    if (character === '/' && css[index + 1] === '*') {
      const commentEnd = css.indexOf('*/', index + 2)
      if (commentEnd === -1) return null
      index = commentEnd + 1
      continue
    }

    if (character === '(') {
      depth++
      if (depth > MAX_CSS_NESTING) return null
      continue
    }

    if (character === ')') {
      if (depth === 0) return null
      depth--
      continue
    }

    if (character === ';' && depth === 0) {
      segments.push(css.slice(segmentStart, index))
      segmentStart = index + 1
    }
  }

  if (quote || depth !== 0) return null
  segments.push(css.slice(segmentStart))

  const declarations: CSSDeclaration[] = []
  for (const segment of segments) {
    const declaration = segment.trim()
    if (!declaration) continue

    let colonIndex = -1
    quote = null
    depth = 0

    for (let index = 0; index < declaration.length; index++) {
      const character = declaration[index] ?? ''

      if (character === '\\') {
        if (index + 1 >= declaration.length) return null
        index = skipRawEscape(declaration, index) - 1
        continue
      }

      if (quote) {
        if (character === quote) quote = null
        continue
      }

      if (character === '"' || character === "'") {
        quote = character
        continue
      }

      if (character === '/' && declaration[index + 1] === '*') {
        const commentEnd = declaration.indexOf('*/', index + 2)
        if (commentEnd === -1) return null
        index = commentEnd + 1
        continue
      }

      if (character === '(') depth++
      else if (character === ')') depth--
      else if (character === ':' && depth === 0) {
        colonIndex = index
        break
      }
    }

    if (colonIndex <= 0) continue

    const property = declaration.slice(0, colonIndex).trim()
    const value = declaration.slice(colonIndex + 1).trim()
    if (property && value) declarations.push({ property, value })
  }

  return declarations
}

function isIdentifierCharacter(character: string): boolean {
  const code = character.charCodeAt(0)
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    character === '-' ||
    character === '_' ||
    code >= 0x80
  )
}

/** Tokenize CSS functions while respecting strings and balanced parentheses. */
function getCSSFunctions(input: string, nesting: number = 0): CSSFunctionToken[] {
  if (nesting > MAX_CSS_NESTING) {
    return [{ name: INVALID_FUNCTION_TOKEN, argument: '' }]
  }

  const functions: CSSFunctionToken[] = []
  let index = 0

  while (index < input.length) {
    const character = input[index] ?? ''

    if (character === '"' || character === "'") {
      const quote = character
      index++
      while (index < input.length && input[index] !== quote) index++
      index++
      continue
    }

    if (!isIdentifierCharacter(character)) {
      index++
      continue
    }

    const nameStart = index
    while (index < input.length && isIdentifierCharacter(input[index] ?? '')) index++
    const name = input.slice(nameStart, index).toLowerCase()

    while (index < input.length && isWhitespace(input[index] ?? '')) index++
    if (input[index] !== '(') continue

    const argumentStart = ++index
    let depth = 1
    let quote: '"' | "'" | null = null

    while (index < input.length && depth > 0) {
      const nested = input[index] ?? ''
      if (quote) {
        if (nested === quote) quote = null
      } else if (nested === '"' || nested === "'") {
        quote = nested
      } else if (nested === '(') {
        depth++
      } else if (nested === ')') {
        depth--
      }
      index++
    }

    const argumentEnd = depth === 0 ? index - 1 : input.length
    const argument = input.slice(argumentStart, argumentEnd)
    functions.push({ name, argument })
    if (functions.length >= MAX_CSS_FUNCTIONS) {
      return [{ name: INVALID_FUNCTION_TOKEN, argument: '' }]
    }

    if (name !== 'url') {
      for (const nestedFunction of getCSSFunctions(argument, nesting + 1)) {
        functions.push(nestedFunction)
        if (functions.length >= MAX_CSS_FUNCTIONS) {
          return [{ name: INVALID_FUNCTION_TOKEN, argument: '' }]
        }
      }
    }
  }

  return functions
}

function hasImportAtRule(input: string): boolean {
  const lower = input.toLowerCase()

  for (let index = 0; index < lower.length; index++) {
    if (lower[index] !== '@') continue
    index++
    while (index < lower.length && isWhitespace(lower[index] ?? '')) index++

    const start = index
    while (index < lower.length && isIdentifierCharacter(lower[index] ?? '')) index++
    if (lower.slice(start, index) === 'import') return true
  }

  return false
}

function getURLFromFunction(argument: string): string | null {
  const trimmed = argument.trim()
  if (!trimmed) return ''

  const first = trimmed[0]
  const last = trimmed[trimmed.length - 1]
  const unquoted = (first === '"' || first === "'") && last === first
    ? trimmed.slice(1, -1).trim()
    : trimmed

  // Nested functions are not valid static URL candidates and can defer the
  // security decision until after sanitization.
  if (unquoted.includes('(') || unquoted.includes(')')) return null
  return unquoted
}

function checkCSSValue(cssValue: string, strictMode: boolean): CSSCheckResult {
  const canonical = canonicalizeCSS(cssValue)
  if (!canonical.valid) {
    return { dangerous: true, reason: 'Malformed CSS comment or escape sequence' }
  }

  for (const token of getCSSFunctions(canonical.value)) {
    if (token.name === INVALID_FUNCTION_TOKEN) {
      return { dangerous: true, reason: 'CSS function nesting or count exceeds the security limit' }
    }

    if (token.name === 'expression') {
      return { dangerous: true, reason: 'Dangerous CSS function: expression()' }
    }

    if (token.name === 'url') {
      if (strictMode) {
        return { dangerous: true, reason: 'CSS url() is not allowed in strict mode' }
      }

      const url = getURLFromFunction(token.argument)
      if (url === null || !isSafeURL(url, CSS_URL_PROTOCOLS)) {
        return { dangerous: true, reason: 'Dangerous or malformed CSS URL' }
      }
    }

    if (RESOURCE_FUNCTION_SET.has(token.name)) {
      return { dangerous: true, reason: `CSS resource function not allowed: ${token.name}()` }
    }

    if (strictMode && STRICT_DYNAMIC_FUNCTION_SET.has(token.name)) {
      return { dangerous: true, reason: `Dynamic CSS function not allowed in strict mode: ${token.name}()` }
    }
  }

  return { dangerous: false }
}

/** Check for constructs that invalidate the complete declaration list. */
export function hasGloballyDangerousCSS(css: string): CSSCheckResult {
  if (!css || typeof css !== 'string') return { dangerous: false }

  const canonical = canonicalizeCSS(css)
  if (!canonical.valid) {
    return { dangerous: true, reason: 'Malformed CSS comment or escape sequence' }
  }

  if (hasImportAtRule(canonical.value)) {
    return { dangerous: true, reason: 'Dangerous CSS at-rule detected: @import' }
  }

  if (getCSSFunctions(canonical.value).some((token) => token.name === 'expression')) {
    return { dangerous: true, reason: 'Dangerous CSS function detected: expression()' }
  }

  return { dangerous: false }
}

/** Check a property value with the same tokenizer used by the sanitizer. */
export function hasDangerousValue(cssValue: string): CSSCheckResult {
  if (!cssValue || typeof cssValue !== 'string') return { dangerous: false }
  return checkCSSValue(cssValue, false)
}

/** Check both list-wide and individual-value security rules. */
export function hasDangerousCSS(css: string): CSSCheckResult {
  const globalCheck = hasGloballyDangerousCSS(css)
  return globalCheck.dangerous ? globalCheck : hasDangerousValue(css)
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
  return FORBIDDEN_CSS_PROPERTY_SET.has(normalized)
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
  return SAFE_CSS_PROPERTY_SET.has(normalized)
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

  const declarations = splitCSSDeclarations(css)
  if (!declarations) return ''

  const safeDeclarations: string[] = []

  for (const declaration of declarations) {
    const canonicalProperty = canonicalizeCSS(declaration.property)
    if (!canonicalProperty.valid) continue

    let propertyName = canonicalProperty.value.toLowerCase().trim()
    // Account for legacy CSS parser hacks such as _behavior and *behavior.
    while (propertyName.startsWith('_') || propertyName.startsWith('*')) {
      propertyName = propertyName.slice(1)
    }

    if (!propertyName || isForbiddenCSSProperty(propertyName)) continue
    if (strictMode && !isSafeCSSProperty(propertyName)) continue
    if (checkCSSValue(declaration.value, strictMode).dangerous) continue

    safeDeclarations.push(`${declaration.property}: ${declaration.value}`)
  }

  return safeDeclarations.join('; ')
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
