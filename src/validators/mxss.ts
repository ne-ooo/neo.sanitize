/**
 * @lpm.dev/neo.sanitize - Mutation XSS (mXSS) Detection
 *
 * Detects and prevents mutation XSS attacks where the browser's HTML parser
 * mutates the HTML in a way that creates vulnerabilities after sanitization.
 *
 * mXSS occurs when:
 * 1. HTML is sanitized
 * 2. Browser parses and "fixes" malformed HTML
 * 3. The mutation creates an XSS vector that wasn't there before
 *
 * Example:
 * ```html
 * <!-- Input -->
 * <svg></p><script>alert(1)</script>
 *
 * <!-- Browser auto-corrects nesting -->
 * <svg></svg><script>alert(1)</script>
 * ```
 *
 * References:
 * - https://cure53.de/fp170.pdf (mXSS paper by Heiderich et al.)
 * - https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/
 */

/**
 * Forbidden tag nesting patterns that can cause mXSS
 *
 * These combinations can cause the browser to auto-correct HTML
 * in ways that create XSS vulnerabilities.
 */
export interface ForbiddenNesting {
  /**
   * Parent tag that creates mXSS risk
   */
  parent: string

  /**
   * Child tags that should not be nested in this parent
   */
  forbiddenChildren: string[]

  /**
   * Reason why this nesting is dangerous
   */
  reason: string
}

/**
 * List of forbidden nesting patterns
 *
 * Each pattern represents a known mXSS vector.
 */
export const FORBIDDEN_NESTING_PATTERNS: readonly ForbiddenNesting[] = [
  {
    parent: 'svg',
    forbiddenChildren: ['p', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li'],
    reason: 'SVG auto-corrects HTML block elements, can create mXSS',
  },
  {
    parent: 'math',
    forbiddenChildren: ['p', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li'],
    reason: 'MathML auto-corrects HTML block elements, can create mXSS',
  },
  {
    parent: 'noscript',
    forbiddenChildren: ['style', 'script', 'meta', 'link'],
    reason: 'Noscript behavior changes with JavaScript enabled/disabled',
  },
  {
    parent: 'noembed',
    forbiddenChildren: ['style', 'script', 'meta', 'link'],
    reason: 'Noembed can cause unexpected parsing',
  },
  {
    parent: 'noframes',
    forbiddenChildren: ['style', 'script', 'meta', 'link'],
    reason: 'Noframes can cause unexpected parsing',
  },
  {
    parent: 'template',
    forbiddenChildren: ['script'],
    reason: 'Template content is inert but can be activated',
  },
  {
    parent: 'form',
    forbiddenChildren: ['form'],
    reason: 'Nested forms cause unexpected behavior',
  },
]

/**
 * Tags that change parsing context (namespace)
 *
 * These tags switch between HTML, SVG, and MathML contexts,
 * which can lead to mXSS if not handled carefully.
 */
export const NAMESPACE_SWITCHING_TAGS: readonly string[] = [
  'svg',
  'math',
]

/**
 * Tags that are particularly dangerous in combination with namespace switching
 */
export const DANGEROUS_IN_FOREIGN_CONTEXT: readonly string[] = [
  'script',
  'style',
  'title',
  'textarea',
  'xmp',
]

/**
 * Check if a tag nesting is forbidden (mXSS risk)
 *
 * @param parentTag - Parent tag name (normalized)
 * @param childTag - Child tag name (normalized)
 * @returns Validation result
 *
 * @example
 * isForbiddenNesting('svg', 'p')  // true - SVG with HTML block element
 * isForbiddenNesting('div', 'p')  // false - Normal HTML nesting
 */
export function isForbiddenNesting(
  parentTag: string,
  childTag: string
): { forbidden: boolean; reason?: string } {
  // Check against forbidden nesting patterns
  for (const pattern of FORBIDDEN_NESTING_PATTERNS) {
    if (pattern.parent === parentTag && pattern.forbiddenChildren.includes(childTag)) {
      return {
        forbidden: true,
        reason: pattern.reason,
      }
    }
  }

  return { forbidden: false }
}

/**
 * Check if a tag switches parsing context (namespace)
 *
 * @param tagName - Tag name to check
 * @returns true if tag switches namespace
 *
 * @example
 * isNamespaceSwitchingTag('svg')  // true
 * isNamespaceSwitchingTag('math')  // true
 * isNamespaceSwitchingTag('div')  // false
 */
export function isNamespaceSwitchingTag(tagName: string): boolean {
  return NAMESPACE_SWITCHING_TAGS.includes(tagName)
}

/**
 * Check if a tag is dangerous in foreign context (SVG/MathML)
 *
 * @param tagName - Tag name to check
 * @returns true if tag is dangerous in foreign context
 *
 * @example
 * isDangerousInForeignContext('script')  // true
 * isDangerousInForeignContext('style')  // true
 * isDangerousInForeignContext('div')  // false
 */
export function isDangerousInForeignContext(tagName: string): boolean {
  return DANGEROUS_IN_FOREIGN_CONTEXT.includes(tagName)
}

/**
 * Validate DOM tree for mXSS patterns
 *
 * Recursively checks a DOM tree for forbidden nesting patterns
 * that could lead to mutation XSS.
 *
 * @param node - DOM node to validate (typically DocumentFragment)
 * @param detectMXSS - Whether to detect mXSS (default: false)
 * @returns Validation result with details
 *
 * @example
 * const fragment = parseHTML('<svg><p>Text</p></svg>')
 * const result = validateMXSS(fragment, true)
 * // { hasMXSS: true, patterns: [...], reason: '...' }
 */
export function validateMXSS(
  node: Node,
  detectMXSS: boolean = false
): {
  hasMXSS: boolean
  patterns?: Array<{ parent: string; child: string; reason: string }>
  reason?: string
} {
  // Skip if mXSS detection is disabled
  if (!detectMXSS) {
    return { hasMXSS: false }
  }

  const forbiddenPatterns: Array<{ parent: string; child: string; reason: string }> = []

  // Recursive function to check nesting
  function checkNode(currentNode: Node, parentTag: string | null = null): void {
    if (currentNode.nodeType !== Node.ELEMENT_NODE) {
      return
    }

    const element = currentNode as Element
    const tagName = element.tagName.toLowerCase()

    // Check if parent/child nesting is forbidden
    if (parentTag) {
      const nestingCheck = isForbiddenNesting(parentTag, tagName)
      if (nestingCheck.forbidden) {
        forbiddenPatterns.push({
          parent: parentTag,
          child: tagName,
          reason: nestingCheck.reason ?? 'Forbidden nesting detected',
        })
      }
    }

    // Check children recursively
    const children = Array.from(element.childNodes)
    for (const child of children) {
      checkNode(child, tagName)
    }
  }

  // Start checking from root
  const children = Array.from(node.childNodes)
  for (const child of children) {
    checkNode(child, null)
  }

  // Return result
  if (forbiddenPatterns.length > 0) {
    return {
      hasMXSS: true,
      patterns: forbiddenPatterns,
      reason: `Found ${forbiddenPatterns.length} forbidden nesting pattern(s)`,
    }
  }

  return { hasMXSS: false }
}

/**
 * Sanitize DOM tree by removing forbidden nesting patterns
 *
 * Removes child elements that are forbidden in their parent context.
 *
 * @param node - DOM node to sanitize (typically DocumentFragment)
 * @param detectMXSS - Whether to detect and fix mXSS (default: false)
 * @returns Number of elements removed
 *
 * @example
 * const fragment = parseHTML('<svg><p>Text</p></svg>')
 * const removed = sanitizeMXSS(fragment, true)
 * // removed = 1, fragment now has <svg></svg>
 */
export function sanitizeMXSS(node: Node, detectMXSS: boolean = false): number {
  // Skip if mXSS detection is disabled
  if (!detectMXSS) {
    return 0
  }

  let removedCount = 0

  // Recursive function to remove forbidden nesting
  function checkAndRemove(currentNode: Node, parentTag: string | null = null): void {
    if (currentNode.nodeType !== Node.ELEMENT_NODE) {
      return
    }

    const element = currentNode as Element
    const tagName = element.tagName.toLowerCase()

    // Check if parent/child nesting is forbidden
    if (parentTag) {
      const nestingCheck = isForbiddenNesting(parentTag, tagName)
      if (nestingCheck.forbidden) {
        // Remove this forbidden element
        if (element.parentNode) {
          element.parentNode.removeChild(element)
          removedCount++
          return // Don't check children of removed element
        }
      }
    }

    // Check children recursively
    const children = Array.from(element.childNodes)
    for (const child of children) {
      checkAndRemove(child, tagName)
    }
  }

  // Start checking from root
  const children = Array.from(node.childNodes)
  for (const child of children) {
    checkAndRemove(child, null)
  }

  return removedCount
}
