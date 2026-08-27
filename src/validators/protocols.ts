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

const DANGEROUS_PROTOCOL_SET = new Set(DANGEROUS_PROTOCOLS)

type ProtocolCollection = readonly string[] | ReadonlySet<string>

function collectionHas(collection: ProtocolCollection, value: string): boolean {
  return 'has' in collection ? collection.has(value) : collection.includes(value)
}

function isASCIIWhitespace(character: string): boolean {
  return character === ' ' || character === '\t' || character === '\n' || character === '\f' || character === '\r'
}

function isSafeCommaSeparatedURLList(
  value: string,
  allowedProtocols: ProtocolCollection
): boolean {
  let candidateStart = 0
  let foundCandidate = false

  for (let index = 0; index <= value.length; index++) {
    if (index < value.length && value[index] !== ',') continue

    const candidate = value.slice(candidateStart, index).trim()
    candidateStart = index + 1
    if (!candidate) continue

    foundCandidate = true
    let urlEnd = 0
    while (
      urlEnd < candidate.length &&
      !isASCIIWhitespace(candidate[urlEnd] ?? '')
    ) {
      urlEnd++
    }

    if (!isSafeURL(candidate.slice(0, urlEnd), allowedProtocols)) return false
  }

  return foundCandidate || value.trim() === ''
}

function isSafeWhitespaceSeparatedURLList(
  value: string,
  allowedProtocols: ProtocolCollection
): boolean {
  let candidateStart = -1
  let foundCandidate = false

  for (let index = 0; index <= value.length; index++) {
    const character = value[index]
    if (character !== undefined && !isASCIIWhitespace(character)) {
      if (candidateStart === -1) candidateStart = index
      continue
    }

    if (candidateStart === -1) continue
    foundCandidate = true
    if (!isSafeURL(value.slice(candidateStart, index), allowedProtocols)) return false
    candidateStart = -1
  }

  return foundCandidate || value.trim() === ''
}

/**
 * Validate every URL carried by an HTML URL attribute.
 */
export function isSafeURLAttributeValue(
  attrName: string,
  value: string,
  allowedProtocols: ProtocolCollection = ALLOWED_PROTOCOLS
): boolean {
  return isSafeURLAttributeValueNormalized(
    attrName.toLowerCase().trim(),
    value,
    allowedProtocols
  )
}

/**
 * Validate a URL attribute whose name is already normalized.
 */
export function isSafeURLAttributeValueNormalized(
  normalizedName: string,
  value: string,
  allowedProtocols: ProtocolCollection = ALLOWED_PROTOCOLS
): boolean {
  if (normalizedName === 'srcset' || normalizedName === 'imagesrcset') {
    return isSafeCommaSeparatedURLList(value, allowedProtocols)
  }

  if (normalizedName === 'ping' || normalizedName === 'attributionsrc') {
    return isSafeWhitespaceSeparatedURLList(value, allowedProtocols)
  }

  return isSafeURL(value, allowedProtocols)
}

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
  const colonIndex = url.indexOf(':')
  if (url.startsWith('/') || url.startsWith('.') || colonIndex === -1) {
    return null // Relative URL, no protocol
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
  allowedProtocols: ProtocolCollection = ALLOWED_PROTOCOLS
): boolean {
  // Null protocol (relative URL) is allowed
  if (protocol === null) {
    return true
  }

  // Check if protocol is in allowed list
  return collectionHas(allowedProtocols, protocol)
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

  return DANGEROUS_PROTOCOL_SET.has(protocol)
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
  allowedProtocols: ProtocolCollection = ALLOWED_PROTOCOLS
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
  allowedProtocols: ProtocolCollection = ALLOWED_PROTOCOLS,
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
  allowedProtocols: ProtocolCollection = ALLOWED_PROTOCOLS
): boolean {
  const protocol = getProtocol(url)
  if (protocol === null) return true
  if (DANGEROUS_PROTOCOL_SET.has(protocol)) return false
  return collectionHas(allowedProtocols, protocol)
}
