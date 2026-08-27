---
name: anti-patterns
description: Common neo.sanitize mistakes involving DOM runtimes, CSS URLs, DOM clobbering, dangerous tags, broad attributes, and DocumentFragment output
version: "1.0.0"
globs:
  - "**/*.ts"
  - "**/*.tsx"
  - "**/*.js"
  - "**/*.jsx"
---

# Anti-Patterns for @lpm.dev/neo.sanitize

### [HIGH] Supply a DOM runtime outside a browser document

Wrong:

```typescript
// Node.js does not provide document or DOMParser.
sanitize(userHtml)
```

Correct:

```typescript
import { JSDOM } from 'jsdom'

const dom = new JSDOM('')
const runtime = {
  document: dom.window.document,
  DOMParser: dom.window.DOMParser,
}

sanitize(userHtml, {}, runtime)
```

Web Workers must also supply a compatible runtime. Use `document` and `DOMParser` from the same DOM implementation.

Source: `src/core/parser.ts`

### [HIGH] Leave inline styles disabled for untrusted content

Wrong:

```typescript
// Strict mode blocks CSS script/resource vectors, but it does not isolate layout.
sanitize('<div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 2147483647">Sign in</div>', {
  allowStyleAttribute: true,
  strictCSSValidation: true,
})
// The overlay-capable properties remain.
```

Correct:

```typescript
sanitize(userHtml)
// allowStyleAttribute remains false. If the product must retain author styles,
// put untrusted content in a separate presentation surface.
```

Both CSS modes remove `expression()`, `@import`, dangerous URL protocols, and forbidden properties. Strict mode also removes URL and dynamic functions, but neither mode prevents UI redressing by itself.

Source: `src/validators/css.ts`

### [HIGH] Do not use `allowAllAttributes` for untrusted content

Wrong:

```typescript
// A broad policy permits id, name, and unknown attributes.
sanitize(userHtml, {
  allowAllAttributes: ['div', 'span', 'p'],
})
// <div id="applicationConfig"> can create a named window property.
```

Correct:

```typescript
// List the required attributes for each tag.
sanitize(userHtml, {
  allowedAttributes: {
    div: ['class'],
    span: ['class'],
    p: ['class'],
  },
  allowClassAttribute: true,
})
```

The sanitizer still removes event handlers, forbidden attributes, dangerous URLs, and dangerous styles. The broad policy permits other attributes.

Source: `src/validators/attributes.ts`

### [HIGH] Enabling `allowIdAttribute` without `preventDOMClobbering` is unsafe

Wrong:

```typescript
// AI enables id attributes without clobbering prevention
sanitize(userHtml, {
  allowIdAttribute: true,
})
// <form id="createElement"> could shadow document.createElement
// <img id="location"> could shadow window.location
```

Correct:

```typescript
// Enable both together
sanitize(userHtml, {
  allowIdAttribute: true,
  preventDOMClobbering: true,
})
// Removes all id and name attributes.

// Better: avoid allowing id attributes on user content entirely
sanitize(userHtml)  // allowIdAttribute: false (default)
```

DOM clobbering lets attackers create browser globals with `id` or `name` attributes. The `preventDOMClobbering` option removes both attributes.

Source: `src/validators/dom-clobbering.ts` — `validateDomClobbering`

### [HIGH] Dangerous tags (script, style, iframe) NEVER preserve text content

Wrong:

```typescript
// AI expects keepTextContent to preserve script/style text
sanitize('<script>const x = 1</script>', { keepTextContent: true })
// Expected: 'const x = 1'
// Actual: '' — script text always removed!

sanitize('<style>body { color: red }</style>', { keepTextContent: true })
// Actual: '' — style text always removed!
```

Correct:

```typescript
// keepTextContent only works for non-dangerous tags
sanitize('<div>Hello</div>', { allowedTags: [] })
// 'Hello' — div text preserved (keepTextContent default: true)

// Dangerous tags always have text removed for security:
// script, style, iframe, object, embed, applet, noscript, template
sanitize('<script>alert(1)</script>')  // ''
sanitize('<style>.x{background:url(evil)}</style>')  // ''

// If you need to extract text from everything, use a DOM parser:
const div = document.createElement('div')
div.innerHTML = html
const text = div.textContent
```

Script and style tag contents are executable/interpretable — preserving their text would be a security risk. This behavior is intentional and cannot be overridden.

Source: `src/core/sanitizer.ts` — dangerous tags skip keepTextContent

### [HIGH] Treat `detectMXSS` as experimental

Wrong:

```typescript
// The sanitizer always removes all foreign namespaces.
sanitize(userSvg, {
  allowedTags: ['svg', 'circle'],
  detectMXSS: true,
})
```

Correct:

```typescript
// Use HTML content only with the experimental mode.
sanitize(userHtml, { detectMXSS: true })
```

The sanitizer always removes foreign namespaces. If three parse passes do not produce stable output, this mode returns empty output.

Source: `src/core/sanitizer.ts` and `src/validators/mxss.ts`

### [HIGH] `data-*` attributes are disabled by default — not a bug

Wrong:

```typescript
// AI expects data attributes to pass through by default
sanitize('<div data-id="123" data-type="user">Hello</div>')
// '<div>Hello</div>' — data attributes stripped!
```

Correct:

```typescript
// Enable data attributes explicitly
sanitize('<div data-id="123" data-type="user">Hello</div>', {
  allowDataAttributes: true,
})
// '<div data-id="123" data-type="user">Hello</div>'

// Or use RELAXED schema which enables them
sanitizeRelaxed('<div data-id="123">Hello</div>')
// '<div data-id="123">Hello</div>'
```

Data attributes are disabled by default because they can leak sensitive information or be used for tracking. Enable them explicitly when needed (e.g., frontend frameworks that use `data-*` for component state).

Source: `src/config/defaults.ts` — allowDataAttributes: false

### [MEDIUM] `class` attribute is disabled by default — CSS collision risk

Wrong:

```typescript
// AI expects class to be allowed
sanitize('<p class="highlight">Important</p>')
// '<p>Important</p>' — class stripped!
```

Correct:

```typescript
// Enable class attribute
sanitize('<p class="highlight">Important</p>', {
  allowClassAttribute: true,
})
// '<p class="highlight">Important</p>'

// Exception: code/pre already allow class in defaults (for syntax highlighting)
sanitize('<code class="language-js">const x = 1</code>')
// '<code class="language-js">const x = 1</code>'

// RELAXED schema enables class globally
sanitizeRelaxed('<p class="highlight">Important</p>')
// '<p class="highlight">Important</p>'
```

Class attributes are disabled by default because user-controlled classes can clash with your CSS, override styles, or exploit CSS-based attacks. The `code`/`pre` tags are exceptions for syntax highlighting support.

Source: `src/config/defaults.ts` — allowClassAttribute: false

### [MEDIUM] URL whitespace is trimmed — `"  javascript:..."` is still caught

Wrong:

```typescript
// AI assumes whitespace-prefixed URLs bypass protocol checks
sanitize('<a href="  javascript:alert(1)">Click</a>')
// AI expects: '<a href="  javascript:alert(1)">Click</a>'
// Actual: '<a>Click</a>' — href removed! Whitespace is trimmed before check.
```

Correct:

```typescript
// All URL attributes are trimmed before protocol validation
// These are ALL caught:
sanitize('<a href="  javascript:alert(1)">Click</a>')    // '<a>Click</a>'
sanitize('<a href="\njavascript:alert(1)">Click</a>')    // '<a>Click</a>'
sanitize('<a href="\tjavascript:alert(1)">Click</a>')    // '<a>Click</a>'

// Relative URLs are always safe (no protocol)
sanitize('<a href="/page">Link</a>')     // '<a href="/page">Link</a>'
sanitize('<a href="//cdn.example.com">CDN</a>')  // '<a href="//cdn.example.com">CDN</a>'
```

Leading/trailing whitespace in URLs is a known XSS bypass vector. neo.sanitize trims all whitespace before extracting and validating the protocol.

Source: `src/validators/protocols.ts` — trim before protocol extraction

### [MEDIUM] `returnString: false` returns DocumentFragment, not string

Wrong:

```typescript
// AI treats result as string when returnString is false
const result = sanitize(html, { returnString: false })
console.log(`Safe HTML: ${result}`)
// 'Safe HTML: [object DocumentFragment]'

db.save({ html: result })  // Saves '[object DocumentFragment]'!
```

Correct:

```typescript
// returnString: true (default) — returns string
const html = sanitize(userHtml)  // string
db.save({ html })  // ✓

// returnString: false — returns DocumentFragment for DOM insertion
const fragment = sanitize(userHtml, { returnString: false })  // DocumentFragment
document.getElementById('content').appendChild(fragment)  // ✓

// If you need both string and DOM:
import { sanitize, serializeHTML } from '@lpm.dev/neo.sanitize'
const fragment = sanitize(html, { returnString: false })
const string = serializeHTML(fragment)  // Convert back to string
```

`returnString: false` is optimized for direct DOM insertion — skip the serialization step. Only use it when you're inserting into the DOM, not when storing or transmitting HTML.

Source: `src/core/sanitizer.ts` — serializeHTML only called when returnString is true

### [MEDIUM] `sanitizeStrict` strips ALL tags — not just dangerous ones

Wrong:

```typescript
// AI uses sanitizeStrict thinking it removes only XSS vectors
sanitizeStrict('<p>Hello <b>World</b></p>')
// Expected: '<p>Hello <b>World</b></p>' (only dangerous tags removed)
// Actual: 'Hello World' (ALL tags removed!)
```

Correct:

```typescript
// sanitizeStrict = text extraction (no HTML at all)
sanitizeStrict('<p>Hello <b>World</b></p>')  // 'Hello World'

// For "remove dangerous, keep safe" — use sanitize() with defaults
sanitize('<p>Hello <b>World</b> <script>evil()</script></p>')
// '<p>Hello <b>World</b> </p>'

// Or use sanitizeBasic for minimal safe HTML
sanitizeBasic('<p>Hello <b>World</b></p>')
// '<p>Hello <b>World</b></p>'
```

The three presets serve different purposes:
- `sanitize()` / `sanitizeRelaxed()` — keep safe HTML, remove dangerous
- `sanitizeBasic()` — keep minimal formatting (text, links, lists)
- `sanitizeStrict()` — extract text only, remove ALL HTML

Source: `src/config/schemas.ts` — STRICT_SCHEMA has allowedTags: []
