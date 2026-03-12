/**
 * @lpm.dev/neo.sanitize - Protocol Validation
 *
 * Validates URL protocols to prevent XSS attacks via:
 * - javascript: URIs
 * - data: URIs (can contain HTML/scripts)
 * - vbscript: URIs (legacy IE)
 * - file: URIs (local file access)
 * - about: URIs (browser internals)
 */

import type { ProtocolValidationResult } from '../types.js'
import { ALLOWED_PROTOCOLS, DANGEROUS_PROTOCOLS } from '../utils/constants.js'

/**
 * Extract protocol from a URL string
 *
 * Handles various URL formats:
 * - Absolute URLs: "https://example.com"
 * - Protocol-relative URLs: "//example.com"
 * - Relative URLs: "/path" or "path"
 * - Protocol-only: "javascript:alert('xss')"
 *
 * @param url - URL string to parse
 * @returns Protocol name (lowercase) or null if no protocol
 *
 * @example
 * getProtocol('https://example.com') // 'https'
 * getProtocol('javascript:alert(1)') // 'javascript'
 * getProtocol('/path') // null (relative URL)
 */
export function getProtocol(url: string): string | null {
  if (!url || typeof url !== 'string') {
    return null
  }

  // Trim whitespace (XSS vector: "  javascript:alert(1)")
  url = url.trim()

  // Check for protocol-relative URLs (//example.com)
  if (url.startsWith('//')) {
    return null // Relative URL, no protocol
  }

  // Check for relative URLs (/path, ./path, ../path, path)
  if (url.startsWith('/') || url.startsWith('.') || !url.includes(':')) {
    return null // Relative URL, no protocol
  }

  // Extract protocol (everything before first colon)
  const colonIndex = url.indexOf(':')
  if (colonIndex === -1) {
    return null
  }

  // Protocol is everything before the colon
  const protocol = url.slice(0, colonIndex).toLowerCase().trim()

  // Empty protocol check
  if (!protocol) {
    return null
  }

  return protocol
}

/**
 * Check if a protocol is allowed
 *
 * @param protocol - Protocol name (lowercase)
 * @param allowedProtocols - List of allowed protocols
 * @returns True if protocol is allowed
 *
 * @example
 * isProtocolAllowed('https', ['http', 'https']) // true
 * isProtocolAllowed('javascript', ['http', 'https']) // false
 */
export function isProtocolAllowed(
  protocol: string | null,
  allowedProtocols: readonly string[] | string[] = ALLOWED_PROTOCOLS
): boolean {
  // Null protocol (relative URL) is allowed
  if (protocol === null) {
    return true
  }

  // Check if protocol is in allowed list
  return allowedProtocols.includes(protocol)
}

/**
 * Check if a protocol is dangerous
 *
 * @param protocol - Protocol name (lowercase)
 * @returns True if protocol is dangerous
 *
 * @example
 * isDangerousProtocol('javascript') // true
 * isDangerousProtocol('data') // true
 * isDangerousProtocol('https') // false
 */
export function isDangerousProtocol(protocol: string | null): boolean {
  if (protocol === null) {
    return false
  }

  return DANGEROUS_PROTOCOLS.includes(protocol)
}

/**
 * Validate a URL protocol
 *
 * Comprehensive protocol validation with detailed result:
 * - Extracts protocol
 * - Checks if allowed
 * - Checks if dangerous
 * - Provides reason for rejection
 *
 * @param url - URL string to validate
 * @param allowedProtocols - List of allowed protocols
 * @returns Protocol validation result
 *
 * @example
 * validateProtocol('https://example.com')
 * // { allowed: true, protocol: 'https', dangerous: false }
 *
 * validateProtocol('javascript:alert(1)')
 * // { allowed: false, protocol: 'javascript', dangerous: true, reason: 'Dangerous protocol' }
 */
export function validateProtocol(
  url: string,
  allowedProtocols: readonly string[] | string[] = ALLOWED_PROTOCOLS
): ProtocolValidationResult {
  // Extract protocol
  const protocol = getProtocol(url)

  // Check if protocol is dangerous (high priority)
  if (isDangerousProtocol(protocol)) {
    return {
      allowed: false,
      protocol,
      dangerous: true,
      reason: `Dangerous protocol: ${protocol}`,
    }
  }

  // Check if protocol is allowed
  const allowed = isProtocolAllowed(protocol, allowedProtocols)

  if (!allowed && protocol !== null) {
    return {
      allowed: false,
      protocol,
      dangerous: false,
      reason: `Protocol not allowed: ${protocol}`,
    }
  }

  // Protocol is allowed (or relative URL)
  return {
    allowed: true,
    protocol,
    dangerous: false,
  }
}

/**
 * Sanitize a URL by removing dangerous protocols
 *
 * If the URL has a dangerous or disallowed protocol:
 * - Returns an empty string (safest approach)
 * - OR returns '#' to preserve link functionality without danger
 *
 * @param url - URL string to sanitize
 * @param allowedProtocols - List of allowed protocols
 * @param fallback - Fallback value for invalid URLs (default: '')
 * @returns Sanitized URL or fallback
 *
 * @example
 * sanitizeURL('https://example.com') // 'https://example.com'
 * sanitizeURL('javascript:alert(1)') // ''
 * sanitizeURL('javascript:alert(1)', undefined, '#') // '#'
 */
export function sanitizeURL(
  url: string,
  allowedProtocols: readonly string[] | string[] = ALLOWED_PROTOCOLS,
  fallback: string = ''
): string {
  const result = validateProtocol(url, allowedProtocols)

  if (result.allowed) {
    return url
  }

  return fallback
}

/**
 * Check if a URL is safe (convenience function)
 *
 * Returns true if URL has a safe protocol (or is relative).
 *
 * @param url - URL string to check
 * @param allowedProtocols - List of allowed protocols
 * @returns True if URL is safe
 *
 * @example
 * isSafeURL('https://example.com') // true
 * isSafeURL('javascript:alert(1)') // false
 * isSafeURL('/path') // true (relative URL)
 */
export function isSafeURL(
  url: string,
  allowedProtocols: readonly string[] | string[] = ALLOWED_PROTOCOLS
): boolean {
  return validateProtocol(url, allowedProtocols).allowed
}
