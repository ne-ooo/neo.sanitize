/**
 * @lpm.dev/neo.sanitize - Core Sanitization Engine
 */

import type {
  DOMRuntime,
  CompiledSanitizeOptions,
  HTMLInsertionContext,
  SanitizeHooks,
  SanitizeOptions,
  Sanitizer,
  TrustedHTMLLike,
  TrustedTypePolicyLike,
} from '../types.js'
import { DEFAULT_OPTIONS } from '../config/defaults.js'
import { mergeOptions, readOwnOption, snapshotOptions } from '../config/options.js'
import type { ResolvedSanitizeOptions } from '../config/options.js'
import { BASIC_SCHEMA, RELAXED_SCHEMA, STRICT_SCHEMA } from '../config/schemas.js'
import {
  consumeAndSerializeHTML,
  parseHTMLContextWithRuntime,
  resolveDOMRuntime,
  serializeHTML,
} from './parser.js'
import {
  isCustomElementNameNormalized,
  isDangerousTagNormalized,
} from '../validators/tags.js'
import { validateAttributeNormalized } from '../validators/attributes.js'
import type { AttributeValidationPolicy } from '../validators/attributes.js'
import { isForeignNamespace, sanitizeMXSS } from '../validators/mxss.js'
import {
  appendNode,
  cloneDOMNode,
  copyChildNodes,
  createDocumentFragment,
  getAttributeAt,
  getAttributeMapLength,
  getAttributeName,
  getAttributeValue,
  getChildNodes,
  getElementAttributes,
  getElementHTML,
  getElementLocalName,
  getFirstChild,
  getLastChild,
  getNextSibling,
  getNodeType,
  getOwnerDocument,
  getParentNode,
  hasReliableDOMSiblingTraversal,
  hasElementAttribute,
  insertBeforeNode,
  removeElementAttribute,
  removeNode,
  setElementAttribute,
  withDOMIntrinsics,
} from '../utils/dom.js'
import {
  createTrustedHTMLAdapter,
  TrustedTypesIntegrationError,
} from '../utils/trusted-types.js'
import type { TrustedHTMLAdapter } from '../utils/trusted-types.js'

const ELEMENT_NODE = 1
const TEXT_NODE = 3
const DOCUMENT_FRAGMENT_NODE = 11
const MAX_MXSS_STABILIZATION_PASSES = 3
type StringSanitizeOptions = Partial<Omit<SanitizeOptions, 'returnString'>> & {
  returnString?: true
}
type FragmentSanitizeOptions = Partial<Omit<SanitizeOptions, 'returnString'>> & {
  returnString: false
}
const EMPTY_OPTIONS: StringSanitizeOptions = Object.freeze({})
const PREFLIGHT_VOID_TAGS = new Set(
  'area base br col embed hr img input link meta param source track wbr'.split(' ')
)
const P_ENDING_TAGS = new Set(
  'address article aside blockquote div dl fieldset footer form h1 h2 h3 h4 h5 h6 header hgroup hr main nav ol p pre section table ul'.split(' ')
)
const PREFLIGHT_TABLE_SECTION_TAGS = new Set('tbody thead tfoot'.split(' '))

interface SanitizationPolicy {
  config: ResolvedSanitizeOptions
  allowedTags: ReadonlySet<string>
  attributes: AttributeValidationPolicy
}

interface TraversalBudget {
  visitedNodes: number
}

interface ChildCursor {
  child: ChildNode | null
  fallbackChildren: ChildNode[] | undefined
  fallbackIndex: number
}

interface StabilizedMXSS {
  fragment: DocumentFragment
  serialized: string
}

const POLICY_CACHE = new WeakMap<ResolvedSanitizeOptions, SanitizationPolicy>()
const COMPILED_CONFIGS = new WeakSet<object>()

/**
 * Some DOM shims expose childNodes but return null from nextSibling. Detect
 * that contract violation once per parent and use a bounded local snapshot.
 */
function createChildCursor(parent: Node): ChildCursor {
  const child = getFirstChild(parent)
  if (hasReliableDOMSiblingTraversal()) {
    return { child, fallbackChildren: undefined, fallbackIndex: -1 }
  }
  if (
    child &&
    getNextSibling(child) === null &&
    child !== getLastChild(parent)
  ) {
    const childNodes = getChildNodes(parent)
    return {
      child,
      fallbackChildren: copyChildNodes(childNodes),
      fallbackIndex: 0,
    }
  }

  return { child, fallbackChildren: undefined, fallbackIndex: -1 }
}

function advanceChildCursor(cursor: ChildCursor, child: ChildNode): void {
  if (cursor.fallbackChildren) {
    cursor.fallbackIndex++
    cursor.child = cursor.fallbackChildren[cursor.fallbackIndex] ?? null
    return
  }

  cursor.child = getNextSibling(child)
}

function getPolicy(config: ResolvedSanitizeOptions): SanitizationPolicy {
  const cached = POLICY_CACHE.get(config)
  if (cached) return cached

  const allowedAttributes = new Map<string, ReadonlySet<string>>()
  for (const [tagName, attributes] of Object.entries(config.allowedAttributes)) {
    allowedAttributes.set(tagName, new Set(attributes))
  }

  const policy: SanitizationPolicy = {
    config,
    allowedTags: new Set(config.allowedTags),
    attributes: {
      forbiddenAttributes: new Set(config.forbiddenAttributes),
      allowAllAttributes: new Set(config.allowAllAttributes),
      allowedAttributes,
      allowedProtocols: new Set(config.allowedProtocols),
    },
  }
  POLICY_CACHE.set(config, policy)
  return policy
}

function resolveOptions(options: Partial<SanitizeOptions>): ResolvedSanitizeOptions {
  if (COMPILED_CONFIGS.has(options)) {
    return options as ResolvedSanitizeOptions
  }

  if (
    options === EMPTY_OPTIONS ||
    options === DEFAULT_OPTIONS ||
    options === BASIC_SCHEMA ||
    options === RELAXED_SCHEMA ||
    options === STRICT_SCHEMA
  ) {
    return options === EMPTY_OPTIONS
      ? DEFAULT_OPTIONS
      : (options as ResolvedSanitizeOptions)
  }

  const prototype = Object.getPrototypeOf(options)
  if (prototype === Object.prototype || prototype === null) {
    let hasOwnOption = false
    for (const key in options) {
      if (Object.prototype.hasOwnProperty.call(options, key)) {
        hasOwnOption = true
        break
      }
    }
    if (!hasOwnOption) return DEFAULT_OPTIONS
  }

  return mergeOptions(DEFAULT_OPTIONS, options)
}

/**
 * Create frozen options and compile their lookup policy for repeated direct
 * sanitize() calls. Hooks remain call-specific and are not part of the result.
 */
export function compileSanitizeOptions(
  options: Partial<Omit<SanitizeOptions, 'hooks'>> = EMPTY_OPTIONS
): CompiledSanitizeOptions {
  if ('hooks' in options) {
    throw new TypeError(
      'compileSanitizeOptions() rejects hooks. Use createSanitizer().'
    )
  }

  const config = snapshotOptions(resolveOptions(options))
  COMPILED_CONFIGS.add(config)
  getPolicy(config)
  return config
}

/**
 * Sanitize an HTML string.
 *
 * @param html - HTML string to sanitize
 * @param options - Sanitization options
 * @param runtime - Optional DOM runtime for Node.js or a Web Worker
 */
export function sanitize(
  html: string,
  options?: StringSanitizeOptions,
  runtime?: DOMRuntime
): string
export function sanitize(
  html: string,
  options: FragmentSanitizeOptions,
  runtime?: DOMRuntime
): DocumentFragment
export function sanitize(
  html: string,
  options?: Partial<SanitizeOptions>,
  runtime?: DOMRuntime
): string | DocumentFragment
export function sanitize(
  html: string,
  options: Partial<SanitizeOptions> = EMPTY_OPTIONS,
  runtime?: DOMRuntime
): string | DocumentFragment {
  const config = resolveOptions(options)
  return sanitizeWithPolicy(
    html,
    getPolicy(config),
    readOwnOption(options, 'hooks'),
    runtime
  )
}

/**
 * Sanitize HTML and return the caller policy's exact TrustedHTML type.
 *
 * The policy must be an identity policy. It is used only for inert parsing and
 * for wrapping the final sanitized output under Trusted Types enforcement.
 */
export function sanitizeToTrustedHTML<TTrustedHTML extends TrustedHTMLLike>(
  html: string,
  trustedTypesPolicy: TrustedTypePolicyLike<TTrustedHTML>,
  options: StringSanitizeOptions = EMPTY_OPTIONS,
  runtime?: DOMRuntime
): TTrustedHTML {
  const config = resolveOptions(options)
  if (!config.returnString) {
    throw new TrustedTypesIntegrationError(
      'sanitizeToTrustedHTML() does not support returnString: false.'
    )
  }

  const dom = resolveDOMRuntime(runtime)
  const trustedHTML = createTrustedHTMLAdapter(
    trustedTypesPolicy,
    dom.document
  )
  const result = sanitizeWithPolicy(
    html,
    getPolicy(config),
    readOwnOption(options, 'hooks'),
    dom,
    trustedHTML
  )
  if (typeof result !== 'string') {
    throw new TrustedTypesIntegrationError(
      'sanitizeToTrustedHTML() did not produce a string result.'
    )
  }

  return trustedHTML.createHTML(result)
}

function isRejectedElementName(
  tagName: string,
  config: ResolvedSanitizeOptions
): boolean {
  return (
    isDangerousTagNormalized(tagName) ||
    (!config.allowCustomElements && isCustomElementNameNormalized(tagName))
  )
}

function isCustomizedBuiltIn(
  element: Element,
  attributes: NamedNodeMap,
  config: ResolvedSanitizeOptions
): boolean {
  return (
    !config.allowCustomElements &&
    getAttributeMapLength(attributes) > 0 &&
    hasElementAttribute(element, 'is')
  )
}

function sanitizeWithPolicy(
  html: string,
  policy: SanitizationPolicy,
  hooks: SanitizeHooks | undefined,
  runtime: DOMRuntime | undefined,
  trustedHTML?: TrustedHTMLAdapter
): string | DocumentFragment {
  const config = policy.config

  if (typeof html !== 'string') {
    if (config.returnString) {
      return ''
    }

    return createDocumentFragment(resolveDOMRuntime(runtime).document)
  }

  let processedHtml = html
  if (processedHtml.length > config.maxInputLength) {
    return config.returnString
      ? ''
      : createDocumentFragment(resolveDOMRuntime(runtime).document)
  }

  if (hooks?.beforeSanitize) {
    const hookResult = hooks.beforeSanitize(html)
    if (typeof hookResult === 'string') {
      processedHtml = hookResult
    }
  }

  // Enforce the limit after beforeSanitize because a hook can replace a small
  // input with a much larger string.
  if (processedHtml.length > config.maxInputLength) {
    return config.returnString
      ? ''
      : createDocumentFragment(resolveDOMRuntime(runtime).document)
  }

  // Give beforeSanitize a chance to replace an empty input, while preserving
  // the no-DOM fast path when no fragment-level hook can produce output.
  if (!processedHtml && !hooks?.afterSanitize) {
    return config.returnString
      ? ''
      : createDocumentFragment(resolveDOMRuntime(runtime).document)
  }

  if (
    exceedsMarkupDepth(
      processedHtml,
      config.maxDOMDepth,
      config.insertionContext
    )
  ) {
    return config.returnString
      ? ''
      : createDocumentFragment(resolveDOMRuntime(runtime).document)
  }

  const dom = resolveDOMRuntime(runtime)
  return withDOMIntrinsics(dom.document, () =>
    sanitizeWithResolvedDOM(
      processedHtml,
      policy,
      hooks,
      dom,
      trustedHTML
    )
  )
}

function sanitizeWithResolvedDOM(
  processedHtml: string,
  policy: SanitizationPolicy,
  hooks: SanitizeHooks | undefined,
  dom: DOMRuntime,
  trustedHTML?: TrustedHTMLAdapter
): string | DocumentFragment {
  const config = policy.config
  const useDirectStringPath =
    config.returnString &&
    !config.detectMXSS &&
    !hooks?.onElement &&
    !hooks?.onAttribute &&
    !hooks?.afterSanitize

  if (useDirectStringPath) {
    let parsedSource: HTMLElement
    try {
      parsedSource = parseHTMLContextWithRuntime(
        processedHtml,
        dom,
        config.insertionContext,
        trustedHTML
      )
    } catch (cause) {
      if (trustedHTML) {
        if (cause instanceof TrustedTypesIntegrationError) throw cause
        throw new TrustedTypesIntegrationError(
          'Trusted Types protected parsing failed.',
          { cause }
        )
      }
      return ''
    }
    if (!sanitizeNodeInPlace(parsedSource, policy)) return ''
    return getElementHTML(parsedSource)
  }

  let parsedSource: HTMLElement
  try {
    parsedSource = parseHTMLContextWithRuntime(
      processedHtml,
      dom,
      config.insertionContext,
      trustedHTML
    )
  } catch (cause) {
    if (trustedHTML) {
      if (cause instanceof TrustedTypesIntegrationError) throw cause
      throw new TrustedTypesIntegrationError(
        'Trusted Types protected parsing failed.',
        { cause }
      )
    }
    return config.returnString ? '' : createDocumentFragment(dom.document)
  }

  // User hooks run only in this pass.
  const traversalHooks = hooks?.onElement || hooks?.onAttribute ? hooks : undefined
  const sanitizedFragment = buildSanitizedFragment(
    parsedSource,
    policy,
    traversalHooks,
    dom.document
  )
  if (!sanitizedFragment) {
    return config.returnString ? '' : createDocumentFragment(dom.document)
  }

  let fragment = sanitizedFragment

  if (config.detectMXSS && hooks?.afterSanitize) {
    sanitizeMXSS(fragment, true)
  }

  let finalFragment = fragment
  if (hooks?.afterSanitize) {
    const hookResult = hooks.afterSanitize(fragment)
    if (isDocumentFragment(hookResult)) {
      finalFragment = hookResult
    }
  }

  if (hooks?.onElement || hooks?.onAttribute || hooks?.afterSanitize) {
    // Hooks can change nodes that the first traversal already processed. This
    // pass has no hooks, so every current element and attribute is revalidated.
    const revalidated = sanitizeNode(finalFragment, policy, undefined, dom.document)
    if (!revalidated) {
      return config.returnString ? '' : createDocumentFragment(dom.document)
    }
    finalFragment = revalidated
  }

  let stabilizedSerialization: string | undefined
  if (config.detectMXSS) {
    sanitizeMXSS(finalFragment, true)
    const stabilized = stabilizeMXSS(finalFragment, policy, dom, trustedHTML)
    finalFragment = stabilized.fragment
    stabilizedSerialization = stabilized.serialized
  }

  if (!config.returnString) return finalFragment
  if (stabilizedSerialization !== undefined) return stabilizedSerialization

  const hooksCanRetainNodes = Boolean(
    hooks?.onElement || hooks?.onAttribute || hooks?.afterSanitize
  )
  return hooksCanRetainNodes
    ? serializeHTML(finalFragment)
    : consumeAndSerializeHTML(finalFragment)
}

/**
 * Reject obviously excessive raw markup nesting before invoking a third-party
 * DOM runtime. The DOM traversal remains authoritative because HTML tree
 * construction can repair malformed markup in ways a bounded preflight cannot.
 */
function exceedsMarkupDepth(
  html: string,
  maximumDepth: number,
  insertionContext: HTMLInsertionContext
): boolean {
  const openTags: Array<{
    name: string
    foreign: boolean
    depthContribution: number
  }> = []
  let trackedDepth = 0
  let openHTMLSelectTags = 0
  let index = 0

  const popOpenTag = (): void => {
    const frame = openTags.pop()
    if (!frame) return
    trackedDepth -= frame.depthContribution
    if (!frame.foreign && frame.name === 'select') openHTMLSelectTags--
  }

  while (index < html.length) {
    const currentFrame = openTags[openTags.length - 1]
    if (!currentFrame?.foreign && currentFrame?.name === 'plaintext') return false
    if (
      !currentFrame?.foreign &&
      currentFrame &&
      PREFLIGHT_RAW_TEXT_TAGS.has(currentFrame.name)
    ) {
      const rawTextEnd = currentFrame.name === 'script'
        ? findScriptTextEnd(html, index)
        : findRawTextEnd(html, index, currentFrame.name)
      if (!rawTextEnd) return false
      popOpenTag()
      index = rawTextEnd
      continue
    }

    const tagStart = html.indexOf('<', index)
    if (tagStart === -1) return false

    if (currentFrame?.foreign && html.startsWith('<![CDATA[', tagStart)) {
      // Foreign namespaces are unsupported and removed. Reject CDATA instead
      // of guessing whether an SVG/MathML integration point returned to HTML.
      return true
    }

    if (html.startsWith('<!--', tagStart)) {
      const commentEnd = findCommentEnd(html, tagStart)
      if (commentEnd === -1) return false
      index = commentEnd
      continue
    }

    const nextCharacter = html[tagStart + 1] ?? ''
    if (nextCharacter === '!' || nextCharacter === '?') {
      const commentEnd = html.indexOf('>', tagStart + 2)
      if (commentEnd === -1) return false
      index = commentEnd + 1
      continue
    }

    const closingTag = nextCharacter === '/'
    const nameStart = tagStart + (closingTag ? 2 : 1)
    if (!isASCIIAlpha(html[nameStart] ?? '')) {
      if (closingTag) {
        const commentEnd = html.indexOf('>', nameStart)
        if (commentEnd === -1) return false
        index = commentEnd + 1
      } else {
        index = tagStart + 1
      }
      continue
    }

    let cursor = nameStart
    while (cursor < html.length && !isHTMLTagNameDelimiter(html[cursor] ?? '')) {
      cursor++
    }

    const tagName = asciiLowercase(html.slice(nameStart, cursor))
    const tagEnd = findTagEnd(html, cursor)
    if (tagEnd === -1) return false

    if (closingTag) {
      // Only trust a close that matches the lexical stack. The HTML parser can
      // ignore malformed or out-of-scope end tags, so wider popping is unsafe.
      if (openTags[openTags.length - 1]?.name === tagName) popOpenTag()
      index = tagEnd
      continue
    }

    if (
      PREFLIGHT_RAW_TEXT_TAGS.has(tagName) &&
      tagName !== 'script' &&
      tagName !== 'textarea' &&
      openHTMLSelectTags > 0
    ) {
      return true
    }

    if (
      openTags[openTags.length - 1]?.foreign &&
      PREFLIGHT_RAW_TEXT_TAGS.has(tagName)
    ) {
      return true
    }

    const top = openTags[openTags.length - 1]
    if (
      !top?.foreign &&
      ((top?.name === 'p' && P_ENDING_TAGS.has(tagName)) ||
      (top?.name === 'li' && tagName === 'li') ||
      ((top?.name === 'dt' || top?.name === 'dd') && (tagName === 'dt' || tagName === 'dd')) ||
      (top?.name === 'tr' && tagName === 'tr') ||
      ((top?.name === 'th' || top?.name === 'td') && (tagName === 'th' || tagName === 'td')) ||
      (top?.name === 'option' && (tagName === 'option' || tagName === 'optgroup')) ||
      ((top?.name === 'thead' || top?.name === 'tbody' || top?.name === 'tfoot') &&
        (tagName === 'thead' || tagName === 'tbody' || tagName === 'tfoot'))
      )
    ) {
      popOpenTag()
    }

    // In HTML, a trailing slash does not close ordinary or custom elements.
    // Count every non-void tag so `<div/>` cannot bypass the parser preflight.
    const parentIsForeign = openTags[openTags.length - 1]?.foreign ?? false
    if (parentIsForeign || !PREFLIGHT_VOID_TAGS.has(tagName)) {
      const depthContribution =
        1 +
        getImplicitTableDepth(
          tagName,
          openTags[openTags.length - 1] ??
            getInsertionContextTableParent(insertionContext)
        )
      const foreign = parentIsForeign || tagName === 'svg' || tagName === 'math'
      openTags.push({
        name: tagName,
        foreign,
        depthContribution,
      })
      trackedDepth += depthContribution
      if (!foreign && tagName === 'select') openHTMLSelectTags++
      if (trackedDepth > maximumDepth) return true
    }

    index = tagEnd
  }

  return false
}

function getInsertionContextTableParent(
  insertionContext: HTMLInsertionContext
): { name: string; foreign: false } | undefined {
  if (
    insertionContext === 'table' ||
    insertionContext === 'thead' ||
    insertionContext === 'tbody' ||
    insertionContext === 'tfoot' ||
    insertionContext === 'tr'
  ) {
    return { name: insertionContext, foreign: false }
  }

  return undefined
}

function getImplicitTableDepth(
  tagName: string,
  parent: { name: string; foreign: boolean } | undefined
): number {
  if (parent?.foreign) return 0

  if (tagName === 'tr') {
    return parent && PREFLIGHT_TABLE_SECTION_TAGS.has(parent.name) ? 0 : 1
  }

  if (tagName === 'td' || tagName === 'th') {
    if (parent?.name === 'tr') return 0
    if (parent && PREFLIGHT_TABLE_SECTION_TAGS.has(parent.name)) return 1
    return 2
  }

  return 0
}

const PREFLIGHT_RAW_TEXT_TAGS = new Set(
  'iframe noembed noframes plaintext script style textarea title xmp'.split(' ')
)

function isASCIIAlpha(character: string): boolean {
  const code = character.charCodeAt(0)
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
}

function isASCIIWhitespace(character: string): boolean {
  return (
    character === ' ' ||
    character === '\t' ||
    character === '\n' ||
    character === '\f' ||
    character === '\r'
  )
}

function isHTMLTagNameDelimiter(character: string): boolean {
  return character === '/' || character === '>' || isASCIIWhitespace(character)
}

function asciiLowercase(value: string): string {
  let result = ''
  for (const character of value) {
    const code = character.charCodeAt(0)
    result += code >= 65 && code <= 90 ? String.fromCharCode(code + 32) : character
  }
  return result
}

/** Find a tag's closing bracket with HTML-compatible attribute states. */
function findTagEnd(html: string, start: number): number {
  let state = 0

  for (let index = start; index < html.length; index++) {
    const character = html[index] ?? ''

    if (state === 4) {
      if (character === '"') state = 7
      continue
    }
    if (state === 5) {
      if (character === "'") state = 7
      continue
    }
    if (state === 6) {
      if (isASCIIWhitespace(character)) state = 0
      else if (character === '>') return index + 1
      continue
    }
    if (state === 1) {
      if (isASCIIWhitespace(character)) state = 2
      else if (character === '/') state = 8
      else if (character === '=') state = 3
      else if (character === '>') return index + 1
      continue
    }
    if (state === 2) {
      if (isASCIIWhitespace(character)) continue
      if (character === '/') state = 8
      else if (character === '=') state = 3
      else if (character === '>') return index + 1
      else state = 1
      continue
    }
    if (state === 3) {
      if (isASCIIWhitespace(character)) continue
      if (character === '"') state = 4
      else if (character === "'") state = 5
      else if (character === '>') return index + 1
      else state = 6
      continue
    }
    if (state === 7) {
      if (isASCIIWhitespace(character)) state = 0
      else if (character === '/') state = 8
      else if (character === '>') return index + 1
      else {
        state = 0
        index--
      }
      continue
    }
    if (state === 8) {
      if (character === '>') return index + 1
      state = 0
      if (!isASCIIWhitespace(character)) index--
      continue
    }

    if (isASCIIWhitespace(character)) continue
    if (character === '/') state = 8
    else if (character === '>') return index + 1
    else state = 1
  }

  return -1
}

/** Return the position after a real HTML comment terminator. */
function findCommentEnd(html: string, start: number): number {
  const contentStart = start + 4
  if (html[contentStart] === '>') return contentStart + 1
  if (html[contentStart] === '-' && html[contentStart + 1] === '>') {
    return contentStart + 2
  }

  const normalEnd = html.indexOf('-->', contentStart)
  const bangEnd = html.indexOf('--!>', contentStart)
  if (normalEnd === -1) return bangEnd === -1 ? -1 : bangEnd + 4
  if (bangEnd === -1 || normalEnd < bangEnd) return normalEnd + 3
  return bangEnd + 4
}

/** Find the appropriate closing token for RAWTEXT, RCDATA, or script data. */
function findRawTextEnd(html: string, start: number, tagName: string): number | null {
  let searchStart = start

  while (searchStart < html.length) {
    const candidate = html.indexOf('</', searchStart)
    if (candidate === -1) return null

    const nameStart = candidate + 2
    if (!isASCIIAlpha(html[nameStart] ?? '')) {
      searchStart = nameStart
      continue
    }

    let nameEnd = nameStart
    while (nameEnd < html.length && !isHTMLTagNameDelimiter(html[nameEnd] ?? '')) {
      nameEnd++
    }

    const candidateName = asciiLowercase(html.slice(nameStart, nameEnd))
    if (candidateName === tagName) {
      const tagEnd = findTagEnd(html, nameEnd)
      return tagEnd === -1 ? null : tagEnd
    }

    searchStart = Math.max(nameEnd, nameStart + 1)
  }

  return null
}

/** Find a real script end tag across escaped and double-escaped script data. */
function findScriptTextEnd(html: string, start: number): number | null {
  let state = 0
  let index = start

  while (index < html.length) {
    if (state === 0 && html.startsWith('<!--', index)) {
      state = 1
      index += 4
      continue
    }

    if (state === 1 && html.startsWith('-->', index)) {
      state = 0
      index += 3
      continue
    }

    if (html[index] !== '<') {
      index++
      continue
    }

    const closingTag = html[index + 1] === '/'
    const nameStart = index + (closingTag ? 2 : 1)
    const nameEnd = findMatchingTagNameEnd(html, nameStart, 'script')
    if (nameEnd === -1) {
      index++
      continue
    }

    if (closingTag) {
      if (state === 2) {
        state = 1
        index = nameEnd + 1
        continue
      }

      const tagEnd = findTagEnd(html, nameEnd)
      return tagEnd === -1 ? null : tagEnd
    }

    if (state === 1) state = 2
    index = nameEnd + 1
  }

  return null
}

function findMatchingTagNameEnd(
  html: string,
  nameStart: number,
  expectedName: string
): number {
  if (!isASCIIAlpha(html[nameStart] ?? '')) return -1

  const nameEnd = nameStart + expectedName.length
  return isHTMLTagNameDelimiter(html[nameEnd] ?? '') &&
    asciiLowercase(html.slice(nameStart, nameEnd)) === expectedName
    ? nameEnd
    : -1
}

/**
 * Sanitize a DOM node and its descendants.
 */
function sanitizeNode(
  node: Node,
  policy: SanitizationPolicy,
  hooks: SanitizeHooks | undefined,
  outputDocument: Document
): DocumentFragment | null {
  if (!hooks && isDocumentFragment(node)) {
    if (!sanitizeNodeInPlace(node, policy)) return null
    return node
  }

  return buildSanitizedFragment(node, policy, hooks, outputDocument)
}

/**
 * Sanitize in place. Rebuild only denied subtrees that must retain children.
 * A shared budget prevents rebuilt descendants from being counted twice.
 */
function sanitizeNodeInPlace(
  node: Node,
  policy: SanitizationPolicy,
  budget: TraversalBudget = { visitedNodes: 0 }
): boolean {
  const config = policy.config
  const stack: Array<ChildCursor & { depth: number }> = [
    { ...createChildCursor(node), depth: 1 },
  ]

  while (stack.length > 0) {
    const frame = stack[stack.length - 1]
    if (!frame) break

    const child = frame.child
    if (!child) {
      stack.pop()
      continue
    }
    advanceChildCursor(frame, child)

    budget.visitedNodes++
    if (budget.visitedNodes > config.maxDOMNodes) return false
    const nodeType = getNodeType(child)
    if (nodeType === ELEMENT_NODE) {
      const element = child as Element
      if (frame.depth > config.maxDOMDepth) return false

      const tagName = getElementLocalName(element).toLowerCase()
      if (
        isForeignNamespace(element, tagName) ||
        isRejectedElementName(tagName, config)
      ) {
        removeNode(element)
        continue
      }
      const attributes = getElementAttributes(element)
      if (isCustomizedBuiltIn(element, attributes, config)) {
        removeNode(element)
        continue
      }

      if (!policy.allowedTags.has(tagName)) {
        if (config.stripTags || config.keepTextContent) {
          const promoted = buildSanitizedFragment(
            element,
            policy,
            undefined,
            getOwnerDocument(element),
            budget,
            frame.depth + 1
          )
          if (!promoted) return false

          const parent = getParentNode(element)
          if (parent) {
            insertBeforeNode(parent, promoted, element)
            removeNode(element)
          }
          continue
        }
        removeNode(element)
        continue
      }

      if (config.stripTags) {
        const promoted = buildSanitizedFragment(
          element,
          policy,
          undefined,
          getOwnerDocument(element),
          budget,
          frame.depth + 1
        )
        if (!promoted) return false

        const parent = getParentNode(element)
        if (parent) {
          insertBeforeNode(parent, promoted, element)
          removeNode(element)
        }
        continue
      }
      sanitizeAttributes(element, tagName, policy, undefined, attributes)
      stack.push({
        ...createChildCursor(element),
        depth: frame.depth + 1,
      })
    } else if (nodeType !== TEXT_NODE) {
      removeNode(child)
    }
  }

  return true
}

/** Build sanitized output while appending each retained node only once. */
function buildSanitizedFragment(
  node: Node,
  policy: SanitizationPolicy,
  hooks: SanitizeHooks | undefined,
  outputDocument: Document,
  budget: TraversalBudget = { visitedNodes: 0 },
  initialDepth = 1
): DocumentFragment | null {
  const config = policy.config
  const output = createDocumentFragment(outputDocument)
  const stack: Array<ChildCursor & {
    depth: number
    destination: Node
  }> = [
    {
      ...createChildCursor(node),
      depth: initialDepth,
      destination: output,
    },
  ]

  while (stack.length > 0) {
    const frame = stack[stack.length - 1]
    if (!frame) break

    const child = frame.child
    if (!child) {
      stack.pop()
      continue
    }

    budget.visitedNodes++
    if (budget.visitedNodes > config.maxDOMNodes) return null

    // Capture the next sibling before hooks or removals can mutate the tree.
    advanceChildCursor(frame, child)

    const nodeType = getNodeType(child)
    if (nodeType === ELEMENT_NODE) {
      const element = child as Element
      const tagName = getElementLocalName(element).toLowerCase()

      // Bound DOM depth before the DOM implementation's own serializer can
      // exhaust the JavaScript stack. Over-limit input fails closed.
      if (frame.depth > config.maxDOMDepth) return null

      // HTML policies are not namespace-aware. Retaining SVG, MathML, or
      // other foreign content would allow active attributes such as
      // xlink:href to bypass the HTML URL policy.
      if (
        isForeignNamespace(element, tagName) ||
        isRejectedElementName(tagName, config)
      ) {
        removeNode(element)
        continue
      }
      const attributes = getElementAttributes(element)
      if (isCustomizedBuiltIn(element, attributes, config)) {
        removeNode(element)
        continue
      }

      if (!policy.allowedTags.has(tagName)) {
        if (config.stripTags || config.keepTextContent) {
          stack.push({
            ...createChildCursor(element),
            depth: frame.depth + 1,
            destination: frame.destination,
          })
        } else {
          // The denied subtree is omitted from the output.
        }
        continue
      }

      if (hooks?.onElement) {
        const hookResult = hooks.onElement(element)
        if (hookResult === false) {
          continue
        }
      }

      sanitizeAttributes(element, tagName, policy, hooks, attributes)
      if (config.stripTags) {
        stack.push({
          ...createChildCursor(element),
          depth: frame.depth + 1,
          destination: frame.destination,
        })
      } else {
        const retainedElement = cloneDOMNode(element, false)
        appendNode(frame.destination, retainedElement)
        stack.push({
          ...createChildCursor(element),
          depth: frame.depth + 1,
          destination: retainedElement,
        })
      }
    } else if (nodeType === TEXT_NODE) {
      appendNode(frame.destination, cloneDOMNode(child, false))
    } else {
      // Comments and all non-text, non-element nodes are omitted.
    }
  }

  return output
}

/**
 * Sanitize all current attributes of an element.
 */
function sanitizeAttributes(
  element: Element,
  tagName: string,
  policy: SanitizationPolicy,
  hooks?: SanitizeHooks,
  attributes: NamedNodeMap = getElementAttributes(element)
): void {
  if (hooks?.onAttribute) {
    const attributeSnapshot: Attr[] = []
    const attributeCount = getAttributeMapLength(attributes)
    for (let index = 0; index < attributeCount; index++) {
      const attribute = getAttributeAt(attributes, index)
      if (attribute) attributeSnapshot.push(attribute)
    }
    for (const attr of attributeSnapshot) {
      sanitizeAttribute(element, tagName, attr, policy, hooks)
    }
    return
  }

  let index = 0
  while (index < getAttributeMapLength(attributes)) {
    const attr = getAttributeAt(attributes, index)
    if (!attr) break

    const removed = sanitizeAttribute(element, tagName, attr, policy)
    if (!removed) index++
  }
}

function sanitizeAttribute(
  element: Element,
  tagName: string,
  attr: Attr,
  policy: SanitizationPolicy,
  hooks?: SanitizeHooks
): boolean {
  const config = policy.config
  const sourceAttrName = getAttributeName(attr)
  // HTML parsers canonicalize attribute names before sanitization. The legacy
  // lowercaseAttributes option is retained as a compatibility no-op.
  const attrName = sourceAttrName.toLowerCase()
  const attrValue = getAttributeValue(attr)

  if (hooks?.onAttribute) {
    const hookResult = hooks.onAttribute(element, attrName, attrValue)
    if (hookResult === false) {
      removeElementAttribute(element, sourceAttrName)
      return true
    }
  }

  const validation = validateAttributeNormalized(
    tagName,
    attrName,
    attrValue,
    config.allowedAttributes,
    config,
    policy.attributes
  )

  if (!validation.allowed) {
    removeElementAttribute(element, sourceAttrName)
    return true
  }

  if (validation.sanitizedValue !== undefined) {
    setElementAttribute(element, sourceAttrName, validation.sanitizedValue)
  }
  return false
}

/**
 * Reparse and sanitize output until serialization is stable.
 *
 * If stability does not occur within the pass limit, return an empty fragment.
 */
function stabilizeMXSS(
  fragment: DocumentFragment,
  policy: SanitizationPolicy,
  runtime: DOMRuntime,
  trustedHTML?: TrustedHTMLAdapter
): StabilizedMXSS {
  let serialized = serializeHTML(fragment)

  for (let pass = 0; pass < MAX_MXSS_STABILIZATION_PASSES; pass++) {
    let sanitized: DocumentFragment | null
    try {
      const parsedSource = parseHTMLContextWithRuntime(
        serialized,
        runtime,
        policy.config.insertionContext,
        trustedHTML
      )
      sanitized = buildSanitizedFragment(
        parsedSource,
        policy,
        undefined,
        runtime.document
      )
    } catch (cause) {
      if (trustedHTML) {
        if (cause instanceof TrustedTypesIntegrationError) throw cause
        throw new TrustedTypesIntegrationError(
          'Trusted Types protected mXSS stabilization failed.',
          { cause }
        )
      }
      return {
        fragment: createDocumentFragment(runtime.document),
        serialized: '',
      }
    }
    if (!sanitized) {
      return {
        fragment: createDocumentFragment(runtime.document),
        serialized: '',
      }
    }
    sanitizeMXSS(sanitized, true)

    const nextSerialized = serializeHTML(sanitized)
    if (nextSerialized === serialized) {
      return { fragment: sanitized, serialized: nextSerialized }
    }

    serialized = nextSerialized
  }

  return {
    fragment: createDocumentFragment(runtime.document),
    serialized: '',
  }
}

function isDocumentFragment(value: unknown): value is DocumentFragment {
  return (
    typeof value === 'object' &&
    value !== null &&
    getNodeType(value as Node) === DOCUMENT_FRAGMENT_NODE
  )
}

/**
 * Create a reusable sanitizer with preset configuration.
 */
export function createSanitizer(
  options: Partial<SanitizeOptions> = EMPTY_OPTIONS,
  runtime?: DOMRuntime
): Sanitizer {
  let config = resolveOptions(options)
  let hooks = readOwnOption(options, 'hooks')

  return {
    sanitize(html: string): string | DocumentFragment {
      return sanitizeWithPolicy(html, getPolicy(config), hooks, runtime)
    },

    getConfig(): Readonly<ResolvedSanitizeOptions> {
      return snapshotOptions(config)
    },

    updateConfig(newOptions: Partial<SanitizeOptions>): void {
      config = mergeOptions(config, newOptions)
      if (Object.prototype.hasOwnProperty.call(newOptions, 'hooks')) {
        hooks = readOwnOption(newOptions, 'hooks')
      }
    },
  }
}

export function sanitizeBasic(html: string, runtime?: DOMRuntime): string {
  return sanitizeWithPolicy(html, getPolicy(BASIC_SCHEMA), undefined, runtime) as string
}

export function sanitizeRelaxed(html: string, runtime?: DOMRuntime): string {
  return sanitizeWithPolicy(html, getPolicy(RELAXED_SCHEMA), undefined, runtime) as string
}

export function sanitizeStrict(html: string, runtime?: DOMRuntime): string {
  return sanitizeWithPolicy(html, getPolicy(STRICT_SCHEMA), undefined, runtime) as string
}
