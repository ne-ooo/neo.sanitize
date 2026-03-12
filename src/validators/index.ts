/**
 * @lpm.dev/neo.sanitize - Validator Exports
 *
 * Tag, attribute, and protocol validation functions.
 */

export {
  getProtocol,
  isProtocolAllowed,
  isDangerousProtocol,
  validateProtocol,
  sanitizeURL,
  isSafeURL,
} from './protocols.js'

export {
  normalizeTagName,
  isTagAllowed,
  isDangerousTag,
  validateTag,
  filterAllowedTags,
  getDangerousTags,
  DANGEROUS_TAGS,
} from './tags.js'

export {
  normalizeAttributeName,
  isEventHandler,
  isDataAttribute,
  isAriaAttribute,
  isURLAttribute,
  isForbiddenAttribute,
  isAttributeAllowed,
  validateAttribute,
  filterAllowedAttributes,
} from './attributes.js'
