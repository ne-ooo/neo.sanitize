/**
 * @lpm.dev/neo.sanitize - DOM Clobbering Prevention
 *
 * Prevents DOM clobbering attacks where HTML elements with id/name
 * attributes override critical DOM properties and JavaScript APIs.
 *
 * Example Attack:
 * ```html
 * <form id="createElement"></form>
 * <script>
 *   document.createElement('div')  // TypeError! createElement is now a form
 * </script>
 * ```
 *
 * References:
 * - https://portswigger.net/web-security/dom-based/dom-clobbering
 * - https://domclob.xyz/domc_wiki/
 */

/**
 * DOM properties that should never be clobbered
 *
 * These include:
 * - Document APIs (createElement, getElementById, etc.)
 * - Window globals (location, document, etc.)
 * - Common framework properties (React, Vue, Angular)
 * - Browser APIs (fetch, localStorage, etc.)
 */
export const DANGEROUS_IDS: readonly string[] = [
  // Document APIs
  'createElement',
  'createElementNS',
  'getElementById',
  'getElementsByTagName',
  'getElementsByClassName',
  'querySelector',
  'querySelectorAll',
  'body',
  'head',
  'documentElement',
  'cookie',
  'domain',
  'referrer',
  'write',
  'writeln',
  'open',
  'close',

  // Window globals
  'window',
  'document',
  'location',
  'navigator',
  'history',
  'screen',
  'console',
  'alert',
  'confirm',
  'prompt',
  'fetch',
  'XMLHttpRequest',
  'eval',
  'Function',
  'setTimeout',
  'setInterval',
  'clearTimeout',
  'clearInterval',

  // Storage APIs
  'localStorage',
  'sessionStorage',
  'indexedDB',

  // Common framework properties
  'React',
  'Vue',
  'Angular',
  'jQuery',
  '$',
  '__vue__',
  '__react__',
  '__REACT_DEVTOOLS_GLOBAL_HOOK__',

  // Browser globals that can be clobbered
  'top',
  'parent',
  'self',
  'frames',
  'frameElement',
  'opener',

  // Common variable names
  'undefined',
  'null',
  'true',
  'false',
  'NaN',
  'Infinity',

  // Prototype pollution risks
  'constructor',
  'prototype',
  '__proto__',
  'hasOwnProperty',
  'isPrototypeOf',
  'propertyIsEnumerable',
  'toString',
  'valueOf',
]

/**
 * Dangerous name attributes for form elements
 *
 * Form elements with these names can clobber form.elements[name]
 * and potentially override important properties.
 */
export const DANGEROUS_NAMES: readonly string[] = [
  // Form API clobbering
  'submit',
  'reset',
  'action',
  'method',
  'enctype',
  'encoding',
  'target',
  'elements',
  'length',

  // HTMLFormControlsCollection properties
  'item',
  'namedItem',

  // Common form field names that could clobber
  'id',
  'name',
  'form',
  'value',
  'checked',
  'disabled',
  'readonly',
  'required',

  // Include all dangerous IDs as dangerous names too
  ...DANGEROUS_IDS,
]

/**
 * Tags that are particularly dangerous for DOM clobbering
 *
 * - form: Can clobber via name attribute
 * - iframe: Can clobber via name attribute
 * - img: Can clobber via name attribute
 * - embed: Can clobber via name attribute
 * - object: Can clobber via name attribute
 */
export const DOM_CLOBBERING_TAGS: readonly string[] = [
  'form',
  'iframe',
  'img',
  'embed',
  'object',
  'input',
  'button',
  'select',
  'textarea',
]

/**
 * Check if an id value could cause DOM clobbering
 *
 * @param id - The id attribute value
 * @returns true if the id is dangerous
 *
 * @example
 * isDangerousId('createElement')  // true
 * isDangerousId('my-button')      // false
 */
export function isDangerousId(id: string): boolean {
  if (!id || typeof id !== 'string') {
    return false
  }

  const normalized = id.toLowerCase().trim()

  // Check against known dangerous IDs
  return DANGEROUS_IDS.some((dangerousId) => {
    return normalized === dangerousId.toLowerCase()
  })
}

/**
 * Check if a name value could cause DOM clobbering
 *
 * @param name - The name attribute value
 * @param tagName - The tag name (some tags are more dangerous)
 * @returns true if the name is dangerous
 *
 * @example
 * isDangerousName('submit', 'input')  // true
 * isDangerousName('username', 'input')  // false
 */
export function isDangerousName(name: string, tagName: string = ''): boolean {
  if (!name || typeof name !== 'string') {
    return false
  }

  const normalized = name.toLowerCase().trim()
  const normalizedTag = tagName.toLowerCase()

  // Form elements are particularly dangerous
  const isFormElement = DOM_CLOBBERING_TAGS.includes(normalizedTag)

  if (isFormElement) {
    // Check against known dangerous names
    return DANGEROUS_NAMES.some((dangerousName) => {
      return normalized === dangerousName.toLowerCase()
    })
  }

  // For non-form elements, only check against critical IDs
  return DANGEROUS_IDS.some((dangerousId) => {
    return normalized === dangerousId.toLowerCase()
  })
}

/**
 * Validate id and name attributes for DOM clobbering
 *
 * @param tagName - The HTML tag name
 * @param attrName - The attribute name ('id' or 'name')
 * @param attrValue - The attribute value
 * @param allowDomClobbering - Whether to allow DOM clobbering (default: false)
 * @returns Validation result
 *
 * @example
 * validateDomClobbering('form', 'id', 'createElement', false)
 * // { allowed: false, reason: 'DOM clobbering: id="createElement"' }
 *
 * validateDomClobbering('div', 'id', 'my-element', false)
 * // { allowed: true }
 */
export function validateDomClobbering(
  tagName: string,
  attrName: string,
  attrValue: string,
  allowDomClobbering: boolean = false
): { allowed: boolean; reason?: string } {
  // If DOM clobbering is explicitly allowed, skip validation
  if (allowDomClobbering) {
    return { allowed: true }
  }

  // Only validate id and name attributes
  if (attrName !== 'id' && attrName !== 'name') {
    return { allowed: true }
  }

  // Check if this is a dangerous id
  if (attrName === 'id' && isDangerousId(attrValue)) {
    return {
      allowed: false,
      reason: `DOM clobbering: id="${attrValue}" could override DOM API`,
    }
  }

  // Check if this is a dangerous name
  if (attrName === 'name' && isDangerousName(attrValue, tagName)) {
    return {
      allowed: false,
      reason: `DOM clobbering: name="${attrValue}" could override DOM property`,
    }
  }

  return { allowed: true }
}

/**
 * Sanitize id/name attributes to prevent DOM clobbering
 *
 * Options:
 * 1. Remove the attribute entirely (safest)
 * 2. Add a prefix to make it safe (e.g., "user-createElement")
 *
 * @param attrValue - The dangerous id/name value
 * @param strategy - How to sanitize ('remove' or 'prefix')
 * @returns Sanitized value or null to remove
 *
 * @example
 * sanitizeDomClobbering('createElement', 'remove')  // null
 * sanitizeDomClobbering('createElement', 'prefix')  // 'user-createElement'
 */
export function sanitizeDomClobbering(
  attrValue: string,
  strategy: 'remove' | 'prefix' = 'remove'
): string | null {
  if (strategy === 'remove') {
    return null
  }

  // Add 'user-' prefix to make it safe
  return `user-${attrValue}`
}
