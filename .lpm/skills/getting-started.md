---
name: getting-started
description: Use neo.sanitize to remove XSS from untrusted HTML. Covers sanitize(), Trusted Types, reusable sanitizers, schemas, options, protocol and CSS checks, DOM clobbering, mXSS detection, hooks, DOM runtimes, subpath imports, and TypeScript types.
version: "1.1.0"
globs:
  - "**/*.ts"
  - "**/*.tsx"
  - "**/*.js"
  - "**/*.jsx"
---

# Getting Started with @lpm.dev/neo.sanitize

## Overview

neo.sanitize is a zero-dependency HTML sanitization library for XSS prevention. It uses browser DOM APIs or an explicit DOM runtime.

The sanitizer removes script tags, event handlers, dangerous protocols, CSS injection, DOM clobbering, and mutation-XSS patterns.

## Quick Start

```typescript
import { sanitize } from '@lpm.dev/neo.sanitize'

// Removes dangerous HTML, keeps safe formatting
sanitize('<p>Hello <script>alert("XSS")</script> World</p>')
// '<p>Hello  World</p>'

sanitize('<a href="javascript:alert(1)">Click</a>')
// '<a>Click</a>'

sanitize('<img src="x" onerror="alert(1)">')
// '<img src="x">'
```

## Preset Schemas

Three built-in presets for common use cases:

```typescript
import { sanitizeBasic, sanitizeRelaxed, sanitizeStrict } from '@lpm.dev/neo.sanitize'

// BASIC — text formatting only (p, br, strong, em, code, links, lists)
sanitizeBasic('<div><p>Hello <strong>World</strong></p><img src="x"></div>')
// '<p>Hello <strong>World</strong></p>'

// RELAXED — rich HTML (images, tables, headings, classes, data attributes)
sanitizeRelaxed('<div class="card"><img src="photo.jpg" alt="Photo"><table><tr><td>Cell</td></tr></table></div>')
// '<div class="card"><img src="photo.jpg" alt="Photo"><table><tbody><tr><td>Cell</td></tr></tbody></table></div>'

// STRICT — text only (all HTML stripped)
sanitizeStrict('<p>Hello <b>World</b></p>')
// 'Hello World'
```

| Preset | Tags | Attributes | Use Case |
|--------|------|------------|----------|
| **Basic** | p, br, strong, em, code, a, lists | href, title on links | Comments, messages |
| **Relaxed** | 50+ tags incl. img, table, headings | Classes, data-*, code highlighting | CMS, rich editors |
| **Strict** | None (text only) | None | Plain text extraction |

## Custom Configuration

```typescript
import { sanitize } from '@lpm.dev/neo.sanitize'

sanitize(html, {
  // Whitelist tags
  allowedTags: ['p', 'a', 'strong', 'em', 'img'],

  // Whitelist attributes per tag
  allowedAttributes: {
    a: ['href', 'title', 'rel'],
    img: ['src', 'alt', 'width', 'height'],
  },

  // Allowed URL protocols
  allowedProtocols: ['http', 'https', 'mailto'],

  // Global attribute flags
  allowDataAttributes: false,    // data-* attributes (default: false)
  allowAriaAttributes: true,     // aria-* attributes (default: true)
  allowClassAttribute: false,    // class attribute (default: false)
  allowIdAttribute: false,       // id attribute (default: false)
  allowStyleAttribute: false,    // style attribute (default: false)
  allowCustomElements: false,    // custom elements (default: false)
  insertionContext: 'body',      // element that receives the output
})
```

The `allowedTags` option cannot enable active-content tags. Tags such as `script`, `style`, `iframe`, and `form` always stay blocked.

The `allowedTags` option cannot enable custom elements by default. Keep `allowCustomElements` disabled for attacker-controlled HTML.

Each URL in `srcset`, `imagesrcset`, `ping`, and `attributionsrc` must have an allowed protocol.

Set `insertionContext` when output goes into `table`, `tbody`, `tr`, `select`, or another supported special element. The context must match the receiving element.

Raw-text, script, style, template, and foreign-namespace contexts are not supported.

## Trusted Types

If the browser enforces Trusted Types, use `sanitizeToTrustedHTML()`.

```typescript
import { sanitizeToTrustedHTML } from '@lpm.dev/neo.sanitize'

const policy = trustedTypes.createPolicy('neo-sanitize', {
  createHTML(input) {
    return input
  },
})

const clean = sanitizeToTrustedHTML(userHtml, policy)
target.innerHTML = clean
```

The policy must be an identity policy. Keep the policy private to this integration.

Do not call the policy directly for a DOM sink. Direct use bypasses sanitization.

For an explicit browser runtime, create the policy in that runtime's realm.

## createSanitizer — Reusable Instance

```typescript
import { createSanitizer } from '@lpm.dev/neo.sanitize'

// Create once with your config
const sanitizer = createSanitizer({
  allowedTags: ['p', 'a', 'strong', 'em', 'br'],
  allowedAttributes: { a: ['href'] },
  allowedProtocols: ['https'],
})

// Reuse for multiple sanitizations
sanitizer.sanitize(userComment1)
sanitizer.sanitize(userComment2)

// Get a detached, frozen configuration snapshot
const config = sanitizer.getConfig()

// Update config dynamically
sanitizer.updateConfig({ allowClassAttribute: true })
```

`getConfig()` returns a detached, frozen snapshot. `updateConfig()` does not change earlier snapshots.

## Node.js and Web Workers

If the required DOM APIs are not global, Node.js and Web Workers must supply a compatible DOM runtime.

```typescript
import { JSDOM } from 'jsdom'
import { sanitize } from '@lpm.dev/neo.sanitize'

const dom = new JSDOM('')
const runtime = {
  document: dom.window.document,
  DOMParser: dom.window.DOMParser,
}

sanitize(userHtml, {}, runtime)
```

Pass the runtime as the second argument to `createSanitizer`. The `document` and `DOMParser` must use the same DOM implementation.

Use `compileSanitizeOptions()` when direct `sanitize()` calls share options but use different runtime arguments. The function returns frozen options and compiles the policy sets once. It does not accept hooks.

Pass the runtime as the second argument to a preset helper. Pass it to `parseHTML` as the second argument.

## What Gets Blocked

### Dangerous Tags (always removed)
`<script>`, `<iframe>`, `<object>`, `<embed>`, `<applet>`, `<style>`, `<link>`, `<form>`, `<input>`, `<button>`, `<select>`, `<textarea>`, `<base>`, `<meta>`, `<noscript>`, `<template>`, `<frameset>`, `<frame>`

### Event Handlers (60+ blocked)
`onclick`, `onerror`, `onload`, `onmouseover`, `onfocus`, `onchange`, `onsubmit`, and all other `on*` attributes.

### Dangerous Protocols
`javascript:`, `data:`, `vbscript:`, `about:`, `file:` — blocked in `href`, `src`, `action`, `cite`, and other URL attributes.

### HTML Comments
Always removed (can contain conditional execution vectors).

## Allowed by Default

### Tags (50+)
Text: `p`, `br`, `span`, `div`, `blockquote`, `pre`, `code`
Headings: `h1`-`h6`
Styling: `strong`, `b`, `em`, `i`, `u`, `s`, `del`, `ins`, `mark`, `small`, `sub`, `sup`
Lists: `ul`, `ol`, `li`, `dl`, `dt`, `dd`
Links & images: `a`, `img`
Tables: `table`, `thead`, `tbody`, `tfoot`, `tr`, `th`, `td`, `caption`
Other: `hr`, `figure`, `figcaption`, `q`, `cite`, `abbr`, `time`, `samp`, `kbd`, `var`

### Attributes (per tag)
- `a`: href, title, rel, target
- `img`: src, alt, title, width, height
- `table`: width, border, cellpadding, cellspacing
- `td`/`th`: colspan, rowspan, align, valign
- `code`/`pre`: class (for syntax highlighting)
- `blockquote`/`q`: cite
- `time`: datetime
- `abbr`: title
- ARIA attributes (`aria-*`) allowed globally by default

## Protocol Validation

```typescript
import { sanitizeURL, isSafeURL } from '@lpm.dev/neo.sanitize'

// Check if URL is safe
isSafeURL('https://example.com')         // true
isSafeURL('javascript:alert(1)')         // false
isSafeURL('data:text/html,...')           // false

// Sanitize URL with fallback
sanitizeURL('javascript:alert(1)')        // '' (empty)
sanitizeURL('javascript:alert(1)', undefined, '#')  // '#' (custom fallback)
sanitizeURL('https://example.com')        // 'https://example.com'

// Relative URLs are always safe
isSafeURL('/path/to/page')               // true
isSafeURL('//cdn.example.com/file')      // true
```

## Returning DocumentFragment

```typescript
// Default: returns string
const html = sanitize(userHtml)  // string

// Return DOM fragment for direct insertion
const fragment = sanitize(userHtml, { returnString: false })
document.body.appendChild(fragment)  // DocumentFragment
```

## Text Content Behavior

```typescript
// keepTextContent: true (default) — safe removed elements are unwrapped
sanitize('<div>Hello <script>evil()</script> World</div>')
// '<div>Hello  World</div>'

sanitize('<section><p>Hello <strong>World</strong></p></section>')
// '<p>Hello <strong>World</strong></p>'

// Dangerous tags (script, style, iframe) NEVER keep text content
sanitize('<script>alert("XSS")</script>')
// '' (script text always removed)

// stripTags: true — remove ALL tags, keep text
sanitize('<p>Hello <b>World</b></p>', { stripTags: true })
// 'Hello World'
```

## Advanced Security Features

### DOM Clobbering Prevention

```typescript
sanitize(html, { preventDOMClobbering: true })
// Removes all id and name attributes.
```

### CSS Injection Protection

```typescript
sanitize(html, {
  allowStyleAttribute: true,
  strictCSSValidation: true,
})
// For trusted layout markup, allows style="" but blocks:
// - expression() (IE)
// - @import
// - url(javascript:)
// - url(data:)
// - all url() and dynamic functions in strict mode
// Only allows listed CSS properties. This is XSS/resource filtering, not
// layout isolation. Keep styles disabled for untrusted content.
```

### Experimental mXSS Defense

```typescript
sanitize(html, { detectMXSS: true })
// SVG, MathML, and other foreign namespaces are always removed.
// Sanitizes each reparsed result without hooks.
// Returns empty output if three passes do not produce stable serialization.
```

This option is experimental. Its behavior can change before the next major release.

## Schema Merging

```typescript
import { mergeSchema } from '@lpm.dev/neo.sanitize'

// Start from a preset, customize specific options
const config = mergeSchema('BASIC', {
  allowDataAttributes: true,
  allowedTags: ['p', 'a', 'strong', 'em', 'br', 'img'],  // Add img
})

sanitize(html, config)
```

## Hooks

```typescript
sanitize(html, {
  hooks: {
    beforeSanitize: (htmlString) => { /* inspect/replace the input string */ },
    onElement: (element) => { /* use element.localName for the tag name */ },
    onAttribute: (element, attrName, attrValue) => { /* per-attribute hook */ },
    afterSanitize: (fragment) => { /* inspect/modify after */ },
  }
})
```

The sanitizer calls each hook once. After `afterSanitize`, a hook-free pass checks all current nodes and attributes.

The default limits are 200,000 input code units, 100,000 DOM nodes per pass, and 1,024 source DOM levels.

If the application needs a smaller boundary, configure `maxInputLength`, `maxDOMNodes`, and `maxDOMDepth`.

## Validator Utilities

```typescript
import {
  isDangerousTag,
  isEventHandler,
  isDangerousProtocol,
  isDataAttribute,
  isAriaAttribute,
  isSafeURL,
} from '@lpm.dev/neo.sanitize'

isDangerousTag('script')           // true
isEventHandler('onclick')          // true
isDangerousProtocol('javascript')  // true
isDataAttribute('data-id')         // true
isAriaAttribute('aria-label')      // true
```

## Subpath Imports

```typescript
// Core only
import { sanitize, createSanitizer, parseHTML, serializeHTML } from '@lpm.dev/neo.sanitize/core'

// Validators only
import { isDangerousTag, isEventHandler, sanitizeURL } from '@lpm.dev/neo.sanitize/validators'

// Schemas only
import { BASIC_SCHEMA, RELAXED_SCHEMA, STRICT_SCHEMA } from '@lpm.dev/neo.sanitize/schemas'
```

## TypeScript Types

```typescript
import type {
  SanitizeOptions,
  DOMParserLike,
  DOMRuntime,
  SanitizeHooks,
  Sanitizer,
  TagValidationResult,
  AttributeValidationResult,
  ProtocolValidationResult,
} from '@lpm.dev/neo.sanitize'
```
