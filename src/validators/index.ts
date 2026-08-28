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
  isSafeURLAttributeValue,
} from './protocols.js'

export {
  normalizeTagName,
  isTagAllowed,
  isDangerousTag,
  isCustomElementNameNormalized,
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
