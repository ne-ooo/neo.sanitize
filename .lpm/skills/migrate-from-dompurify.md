---
name: migrate-from-dompurify
description: Migration guide from DOMPurify and sanitize-html to neo.sanitize — same security model, preset schemas (basic/relaxed/strict), createSanitizer for reusable instances, built-in protocol/CSS/DOM-clobbering/mXSS validators, TypeScript native, tree-shakeable, zero dependencies, subpath imports
version: "1.0.0"
globs:
  - "**/*.ts"
  - "**/*.tsx"
  - "**/*.js"
  - "**/*.jsx"
---

# Migrating from DOMPurify / sanitize-html to @lpm.dev/neo.sanitize

## Why Migrate

| | DOMPurify | sanitize-html | neo.sanitize |
|---|-----------|---------------|--------------|
| **Bundle** | ~15 KB | ~45 KB | ~8 KB |
| **Dependencies** | Zero | 10+ | Zero |
| **Tree-shaking** | No | No | Yes |
| **TypeScript** | `@types/dompurify` | Built-in (partial) | Built-in |
| **ESM** | Partial | CommonJS | ESM + CJS |
| **Preset schemas** | No | No | Yes (3 presets) |
| **Reusable instance** | createDOMPurify() | No | createSanitizer() |
| **Protocol validation** | Built-in | Built-in | Built-in + utilities |
| **CSS validation** | Built-in | No | Built-in |
| **DOM clobbering** | Built-in | No | Built-in |

## Migrating from DOMPurify

### Basic Usage

```typescript
// Before — DOMPurify
import DOMPurify from 'dompurify'

DOMPurify.sanitize('<p>Hello <script>alert(1)</script></p>')
// '<p>Hello </p>'

// After — neo.sanitize
import { sanitize } from '@lpm.dev/neo.sanitize'

sanitize('<p>Hello <script>alert(1)</script></p>')
// '<p>Hello </p>'
```

### Configuration Mapping

```typescript
// DOMPurify config → neo.sanitize config

// ALLOWED_TAGS → allowedTags
DOMPurify.sanitize(html, { ALLOWED_TAGS: ['p', 'a', 'strong'] })
sanitize(html, { allowedTags: ['p', 'a', 'strong'] })

// ALLOWED_ATTR → allowedAttributes
DOMPurify.sanitize(html, { ALLOWED_ATTR: ['href', 'class'] })
sanitize(html, {
  allowedAttributes: { a: ['href'] },
  allowClassAttribute: true,
})

// ALLOWED_URI_REGEXP → allowedProtocols
DOMPurify.sanitize(html, { ALLOWED_URI_REGEXP: /^https?:/ })
sanitize(html, { allowedProtocols: ['http', 'https'] })

// RETURN_DOM_FRAGMENT → returnString: false
DOMPurify.sanitize(html, { RETURN_DOM_FRAGMENT: true })
sanitize(html, { returnString: false })

// FORBID_TAGS → use allowedTags (whitelist approach)
DOMPurify.sanitize(html, { FORBID_TAGS: ['style', 'form'] })
// neo.sanitize uses whitelist, not blacklist — specify what's allowed

// FORBID_ATTR → forbiddenAttributes
DOMPurify.sanitize(html, { FORBID_ATTR: ['style', 'class'] })
sanitize(html, { forbiddenAttributes: ['style', 'class'] })

// KEEP_CONTENT → keepTextContent
DOMPurify.sanitize(html, { KEEP_CONTENT: false })
sanitize(html, { keepTextContent: false })
```

### Key Differences from DOMPurify

**1. Whitelist vs Blacklist:**
```typescript
// DOMPurify — defaults allow most tags, you FORBID specific ones
DOMPurify.sanitize(html, { FORBID_TAGS: ['form', 'input'] })

// neo.sanitize — you ALLOW specific tags (safer default)
sanitize(html, { allowedTags: ['p', 'a', 'strong', 'em'] })
// Unspecified tags are removed
```

**2. Attribute control is per-tag:**
```typescript
// DOMPurify — global attribute list
DOMPurify.sanitize(html, { ALLOWED_ATTR: ['href', 'src', 'class'] })

// neo.sanitize — per-tag attribute control
sanitize(html, {
  allowedAttributes: {
    a: ['href', 'title', 'rel'],
    img: ['src', 'alt', 'width', 'height'],
  },
  allowClassAttribute: true,  // Global flag for class
})
```

**3. Separate flags for common attributes:**
```typescript
// DOMPurify — class/id/style controlled via ALLOWED_ATTR
DOMPurify.sanitize(html, { ALLOWED_ATTR: ['class', 'id', 'style'] })

// neo.sanitize — explicit boolean flags (clearer intent)
sanitize(html, {
  allowClassAttribute: true,
  allowIdAttribute: true,
  allowStyleAttribute: true,
  strictCSSValidation: true,  // Validate style content
  preventDOMClobbering: true, // Validate id/name values
})
```

### Hooks Migration

```typescript
// Before — DOMPurify hooks
DOMPurify.addHook('beforeSanitizeElements', (node) => { ... })
DOMPurify.addHook('afterSanitizeAttributes', (node) => { ... })

// After — neo.sanitize hooks (per-call, not global)
sanitize(html, {
  hooks: {
    beforeSanitize: (fragment) => { ... },
    onElement: (element, tagName) => { ... },
    onAttribute: (element, attrName, attrValue) => { ... },
    afterSanitize: (fragment) => { ... },
  }
})
```

**Key difference:** DOMPurify hooks are registered globally and persist across calls. neo.sanitize hooks are passed per-call — no global state, no cleanup needed.

### createDOMPurify → createSanitizer

```typescript
// Before — DOMPurify instance
const purify = createDOMPurify(window)
purify.sanitize(html)

// After — neo.sanitize instance
const sanitizer = createSanitizer({
  allowedTags: ['p', 'a', 'strong'],
  allowedAttributes: { a: ['href'] },
})
sanitizer.sanitize(html)

// Update config dynamically
sanitizer.updateConfig({ allowClassAttribute: true })
```

## Migrating from sanitize-html

### Basic Usage

```typescript
// Before — sanitize-html
import sanitizeHtml from 'sanitize-html'

sanitizeHtml('<p>Hello <script>alert(1)</script></p>')
// '<p>Hello </p>'

// After — neo.sanitize
import { sanitize } from '@lpm.dev/neo.sanitize'

sanitize('<p>Hello <script>alert(1)</script></p>')
// '<p>Hello </p>'
```

### Configuration Mapping

```typescript
// sanitize-html config → neo.sanitize config

// allowedTags → allowedTags (same name!)
sanitizeHtml(html, { allowedTags: ['p', 'a'] })
sanitize(html, { allowedTags: ['p', 'a'] })

// allowedAttributes → allowedAttributes (same name and format!)
sanitizeHtml(html, {
  allowedAttributes: { a: ['href', 'title'] }
})
sanitize(html, {
  allowedAttributes: { a: ['href', 'title'] }
})

// allowedSchemes → allowedProtocols
sanitizeHtml(html, { allowedSchemes: ['http', 'https', 'mailto'] })
sanitize(html, { allowedProtocols: ['http', 'https', 'mailto'] })

// allowedClasses → allowClassAttribute + CSS class filtering via hooks
sanitizeHtml(html, { allowedClasses: { p: ['highlight'] } })
sanitize(html, {
  allowClassAttribute: true,
  // Use hooks for class-level filtering if needed
})

// textFilter → hooks.afterSanitize or post-processing
// transformTags → hooks.onElement

// disallowedTagsMode: 'escape' → not directly supported
// neo.sanitize removes tags; use hooks for escape behavior

// nestingLimit → not directly supported
// neo.sanitize handles nesting via mXSS detection
```

### Key Differences from sanitize-html

**1. No `allowedSchemesByTag`:**
```typescript
// sanitize-html — per-tag protocol rules
sanitizeHtml(html, {
  allowedSchemesByTag: { img: ['http', 'https', 'data'] }
})

// neo.sanitize — global protocol list
// data: is always blocked (dangerous). Use a post-processor for data: images
sanitize(html, { allowedProtocols: ['http', 'https'] })
```

**2. No `transformTags`:**
```typescript
// sanitize-html — transform tags
sanitizeHtml(html, {
  transformTags: { b: 'strong', i: 'em' }
})

// neo.sanitize — use onElement hook
sanitize(html, {
  hooks: {
    onElement: (element, tagName) => {
      // Transform in hook
    }
  }
})
```

**3. Presets (neo.sanitize exclusive):**
```typescript
// sanitize-html — no presets, manual config every time
sanitizeHtml(html, { allowedTags: ['p', 'a', 'strong', ...] })

// neo.sanitize — three presets
sanitizeBasic(html)    // Comments, messages
sanitizeRelaxed(html)  // CMS, rich editors
sanitizeStrict(html)   // Text extraction
```

## New Features in neo.sanitize

### Preset Schemas

```typescript
import { sanitizeBasic, sanitizeRelaxed, sanitizeStrict, mergeSchema } from '@lpm.dev/neo.sanitize'

// Use as-is
sanitizeBasic(html)

// Or merge with custom options
const config = mergeSchema('BASIC', { allowDataAttributes: true })
sanitize(html, config)
```

### Validator Utilities

```typescript
import {
  isDangerousTag,
  isEventHandler,
  isSafeURL,
  sanitizeURL,
  isDangerousProtocol,
  sanitizeCSS,
} from '@lpm.dev/neo.sanitize'

// Use validators independently — no need to run full sanitization
isDangerousTag('script')           // true
isEventHandler('onclick')          // true
isSafeURL('javascript:alert(1)')   // false
sanitizeCSS('color: red; expression(alert(1))')  // 'color: red;'
```

### DOM Clobbering Prevention

```typescript
// Neither DOMPurify nor sanitize-html expose this as a utility
import { isDangerousId, isDangerousName } from '@lpm.dev/neo.sanitize'

isDangerousId('createElement')  // true
isDangerousName('submit', 'form')  // true
```

### Subpath Imports

```typescript
// Import only what you need
import { sanitize } from '@lpm.dev/neo.sanitize/core'
import { isDangerousTag, sanitizeURL } from '@lpm.dev/neo.sanitize/validators'
import { BASIC_SCHEMA } from '@lpm.dev/neo.sanitize/schemas'
```

## Migration Checklist

### From DOMPurify
- [ ] Replace `import DOMPurify from 'dompurify'` with `import { sanitize } from '@lpm.dev/neo.sanitize'`
- [ ] Replace `DOMPurify.sanitize(html)` with `sanitize(html)`
- [ ] Convert `ALLOWED_TAGS` → `allowedTags` (lowercase)
- [ ] Convert `ALLOWED_ATTR` → `allowedAttributes` (per-tag format)
- [ ] Convert `FORBID_TAGS` → use whitelist `allowedTags` instead
- [ ] Convert global hooks to per-call `hooks` option
- [ ] Replace `RETURN_DOM_FRAGMENT` with `returnString: false`
- [ ] Replace `createDOMPurify()` with `createSanitizer()`
- [ ] Remove `@types/dompurify` (types built-in)
- [ ] Remove `dompurify` from dependencies

### From sanitize-html
- [ ] Replace `import sanitizeHtml from 'sanitize-html'` with `import { sanitize } from '@lpm.dev/neo.sanitize'`
- [ ] `allowedTags` and `allowedAttributes` — same format, minimal changes
- [ ] Convert `allowedSchemes` → `allowedProtocols`
- [ ] Replace `allowedClasses` with `allowClassAttribute: true` + hooks
- [ ] Replace `transformTags` with `hooks.onElement`
- [ ] Consider using presets (`sanitizeBasic`, `sanitizeRelaxed`) instead of manual config
- [ ] Remove `sanitize-html` and its 10+ transitive dependencies
