---
name: getting-started
description: How to use neo.sanitize — sanitize() for XSS-safe HTML, createSanitizer() for reusable instances, preset schemas (sanitizeBasic, sanitizeRelaxed, sanitizeStrict), allowedTags/allowedAttributes/allowedProtocols configuration, data/aria/class/id/style attribute flags, returnString vs DocumentFragment, protocol validation (blocks javascript:/data:/vbscript:), DOM clobbering prevention, CSS injection protection, mXSS detection, hooks, subpath imports, TypeScript types
version: "1.0.0"
globs:
  - "**/*.ts"
  - "**/*.tsx"
  - "**/*.js"
  - "**/*.jsx"
---

# Getting Started with @lpm.dev/neo.sanitize

## Overview

neo.sanitize is a zero-dependency HTML sanitization library for XSS prevention. Works in browsers and Node.js. Blocks script tags, event handlers (60+ variations), dangerous protocols, CSS injection, DOM clobbering, and mXSS patterns. TypeScript-first, tree-shakeable.

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
sanitizeRelaxed('<div class="card"><img src="photo.jpg" alt="Photo"><table>...</table></div>')
// '<div class="card"><img src="photo.jpg" alt="Photo"><table>...</table></div>'

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
})
```

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

// Inspect current config
const config = sanitizer.getConfig()

// Update config dynamically
sanitizer.updateConfig({ allowClassAttribute: true })
```

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
// keepTextContent: true (default) — text from removed tags is preserved
sanitize('<div>Hello <script>evil()</script> World</div>')
// '<div>Hello  World</div>'

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
// Blocks id/name attributes that could shadow global DOM properties
// e.g., <form id="createElement"> would be blocked
```

### CSS Injection Protection

```typescript
sanitize(html, {
  allowStyleAttribute: true,
  strictCSSValidation: true,
})
// Allows style="" but blocks:
// - expression() (IE)
// - @import
// - url(javascript:)
// - url(data:)
// Only allows 70+ safe CSS properties (color, font-size, margin, etc.)
```

### mXSS Detection

```typescript
sanitize(html, { detectMXSS: true })
// Detects and removes mutation XSS patterns:
// - SVG/MathML with HTML block elements
// - Nested forms
// - template with script
```

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
    beforeSanitize: (fragment) => { /* inspect/modify before */ },
    onElement: (element, tagName) => { /* per-element hook */ },
    onAttribute: (element, attrName, attrValue) => { /* per-attribute hook */ },
    afterSanitize: (fragment) => { /* inspect/modify after */ },
  }
})
```

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
  SanitizeHooks,
  Sanitizer,
  TagValidationResult,
  AttributeValidationResult,
  ProtocolValidationResult,
} from '@lpm.dev/neo.sanitize'
```
