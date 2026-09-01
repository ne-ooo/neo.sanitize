import {
  BASIC_SCHEMA,
  compileSanitizeOptions,
  createSanitizer,
  getSchema,
  mergeSchema,
  sanitize,
  sanitizeToTrustedHTML,
} from '../../src/index.js'
import type {
  DOMRuntime,
  SanitizeOptions,
  TrustedHTMLLike,
  TrustedTypePolicyLike,
} from '../../src/index.js'

declare const html: string
declare const runtime: DOMRuntime
declare const trustedTypesPolicy: TrustedTypePolicyLike<TrustedHTMLLike>

const defaultResult: string = sanitize(html)
const explicitStringResult: string = sanitize(html, { returnString: true }, runtime)
const fragmentResult: DocumentFragment = sanitize(
  html,
  { returnString: false },
  runtime
)
document.body.appendChild(sanitize(html, { returnString: false }, runtime))

declare const widenedOptions: SanitizeOptions
const widenedResult: string | DocumentFragment = sanitize(
  html,
  widenedOptions,
  runtime
)

const schemaWithHooks = mergeSchema('BASIC', {
  hooks: { beforeSanitize: () => '<p>Hooked</p>' },
})
schemaWithHooks.hooks?.beforeSanitize?.(html)

const compiled = compileSanitizeOptions({ allowedTags: ['p'] })
const snapshot = createSanitizer().getConfig()
// @ts-expect-error Compiled collections are deeply readonly.
compiled.allowedTags.push('img')
// @ts-expect-error Sanitizer snapshots are deeply readonly.
snapshot.allowedAttributes.a?.push('onclick')
// @ts-expect-error Built-in schemas are deeply readonly.
BASIC_SCHEMA.allowedTags.push('img')
// @ts-expect-error getSchema returns deeply readonly configuration.
getSchema('BASIC').allowedProtocols.push('javascript')

// @ts-expect-error Fragment output is not a string.
const invalidStringResult: string = sanitize(
  html,
  { returnString: false },
  runtime
)

// @ts-expect-error TrustedHTML output cannot request a DocumentFragment.
sanitizeToTrustedHTML(html, trustedTypesPolicy, { returnString: false }, runtime)

void defaultResult
void explicitStringResult
void fragmentResult
void widenedResult
void invalidStringResult
