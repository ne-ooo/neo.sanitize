/**
 * @lpm.dev/neo.sanitize - Tag Validation
 *
 * Validates HTML tags against a whitelist to prevent XSS attacks via:
 * - <script> tags
 * - <iframe> tags (can load malicious content)
 * - <object>, <embed> tags (can execute code)
 * - <style> tags (CSS injection)
 * - <link> tags (external resource injection)
 * - <form>, <input>, <button> tags (phishing, CSRF)
 * - <base> tags (URL hijacking)
 */

import type { TagValidationResult } from '../types.js'
import { DEFAULT_ALLOWED_TAGS } from '../utils/constants.js'

/**
 * Dangerous HTML tags that should never be allowed
 *
 * These tags can execute code or inject malicious content:
 * - script: Direct JavaScript execution
 * - iframe: Can load any URL, including malicious sites
 * - object, embed: Can load plugins, Flash, etc.
 * - style, link: CSS injection (expression(), @import)
 * - form, input, button: Phishing, form hijacking
 * - base: Can redirect all relative URLs
 * - meta: Can redirect via refresh
 */
export const DANGEROUS_TAGS: readonly string[] = [
  'script',
  'iframe',
  'object',
  'embed',
  'applet',
  'style',
  'link',
  'form',
  'input',
  'button',
  'select',
  'textarea',
  'option',
  'optgroup',
  'base',
  'meta',
  'noscript',
  'template',
  'frameset',
  'frame',
  'noframes',
] as const

/**
 * Normalize tag name to lowercase
 *
 * HTML tag names are case-insensitive, but we normalize to lowercase
 * for consistent comparison.
 *
 * @param tagName - Tag name to normalize
 * @returns Normalized tag name (lowercase)
 *
 * @example
 * normalizeTagName('DIV') // 'div'
 * normalizeTagName('Script') // 'script'
 */
export function normalizeTagName(tagName: string): string {
  return tagName.toLowerCase().trim()
}

/**
 * Check if a tag is allowed
 *
 * @param tagName - Tag name to check (case-insensitive)
 * @param allowedTags - List of allowed tags
 * @returns True if tag is allowed
 *
 * @example
 * isTagAllowed('p', DEFAULT_ALLOWED_TAGS) // true
 * isTagAllowed('script', DEFAULT_ALLOWED_TAGS) // false
 * isTagAllowed('DIV', DEFAULT_ALLOWED_TAGS) // true (normalized to 'div')
 */
export function isTagAllowed(
  tagName: string,
  allowedTags: readonly string[] | string[] = DEFAULT_ALLOWED_TAGS
): boolean {
  const normalized = normalizeTagName(tagName)
  return allowedTags.includes(normalized)
}

/**
 * Check if a tag is dangerous
 *
 * @param tagName - Tag name to check (case-insensitive)
 * @returns True if tag is dangerous
 *
 * @example
 * isDangerousTag('script') // true
 * isDangerousTag('iframe') // true
 * isDangerousTag('p') // false
 */
export function isDangerousTag(tagName: string): boolean {
  const normalized = normalizeTagName(tagName)
  return DANGEROUS_TAGS.includes(normalized)
}

/**
 * Validate a tag name
 *
 * Comprehensive tag validation with detailed result:
 * - Normalizes tag name to lowercase
 * - Checks if allowed
 * - Provides reason for rejection
 *
 * @param tagName - Tag name to validate
 * @param allowedTags - List of allowed tags
 * @returns Tag validation result
 *
 * @example
 * validateTag('p')
 * // { allowed: true, tagName: 'p' }
 *
 * validateTag('script')
 * // { allowed: false, tagName: 'script', reason: 'Tag not allowed' }
 *
 * validateTag('DIV', ['div', 'span'])
 * // { allowed: true, tagName: 'div' } (normalized)
 */
export function validateTag(
  tagName: string,
  allowedTags: readonly string[] | string[] = DEFAULT_ALLOWED_TAGS
): TagValidationResult {
  const normalized = normalizeTagName(tagName)

  // Check if tag is in allowed list
  const allowed = allowedTags.includes(normalized)

  if (!allowed) {
    return {
      allowed: false,
      tagName: normalized,
      reason: isDangerousTag(normalized)
        ? `Dangerous tag: ${normalized}`
        : `Tag not allowed: ${normalized}`,
    }
  }

  return {
    allowed: true,
    tagName: normalized,
  }
}

/**
 * Filter allowed tags from a list
 *
 * Returns only tags that are in the allowed list.
 *
 * @param tagNames - List of tag names to filter
 * @param allowedTags - List of allowed tags
 * @returns Filtered list of allowed tag names (lowercase)
 *
 * @example
 * filterAllowedTags(['p', 'script', 'div'])
 * // ['p', 'div']
 *
 * filterAllowedTags(['SCRIPT', 'DIV', 'IFRAME'], ['div', 'span'])
 * // ['div']
 */
export function filterAllowedTags(
  tagNames: string[],
  allowedTags: readonly string[] | string[] = DEFAULT_ALLOWED_TAGS
): string[] {
  return tagNames
    .map(normalizeTagName)
    .filter((tagName) => allowedTags.includes(tagName))
}

/**
 * Get dangerous tags from a list
 *
 * Returns only tags that are dangerous.
 *
 * @param tagNames - List of tag names to check
 * @returns List of dangerous tag names (lowercase)
 *
 * @example
 * getDangerousTags(['p', 'script', 'div', 'iframe'])
 * // ['script', 'iframe']
 */
export function getDangerousTags(tagNames: string[]): string[] {
  return tagNames.map(normalizeTagName).filter((tagName) => DANGEROUS_TAGS.includes(tagName))
}
