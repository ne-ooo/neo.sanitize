# @lpm.dev/neo.sanitize

**Browser-native HTML sanitization with zero dependencies**

Fast, secure, and lightweight HTML sanitization library that prevents XSS attacks using the browser's native DOMParser. No runtime dependencies, tree-shakeable, and TypeScript-first.

## Features

✅ **Zero Dependencies** - Uses native browser DOMParser
✅ **Secure by Default** - Blocks 143+ XSS vectors (OWASP compliant)
✅ **Tree-Shakeable** - Import only what you need
✅ **TypeScript-First** - Full type safety with strict mode
✅ **Predefined Schemas** - BASIC, RELAXED, STRICT configurations
✅ **Customizable** - Fine-grained control over tags, attributes, and protocols
✅ **Cross-Realm Safe** - Works in iframes and workers
✅ **Lightweight** - < 3 KB gzipped

## Installation

```bash
lpm install @lpm.dev/neo.sanitize
```

## Quick Start

```typescript
import { sanitize } from '@lpm.dev/neo.sanitize'

// Basic usage - sanitize HTML string
const clean = sanitize('<p>Hello <strong>world</strong>!</p>')
// Output: '<p>Hello <strong>world</strong>!</p>'

// Removes dangerous content
const safe = sanitize('<p onclick="alert(1)">Click</p><script>alert(1)</script>')
// Output: '<p>Click</p>'
```

## Security Features

### XSS Protection (143 Test Vectors)

**Blocks Script Injection:**
```typescript
sanitize('<script>alert("XSS")</script>')  // ''
sanitize('<p>Safe</p><script>alert(1)</script>')  // '<p>Safe</p>'
```

**Removes Event Handlers:**
```typescript
sanitize('<div onclick="alert(1)">Click</div>')  // '<div>Click</div>'
sanitize('<img src=x onerror="alert(1)">')  // '<img src="x">'
```

**Validates URL Protocols:**
```typescript
sanitize('<a href="javascript:alert(1)">Click</a>')  // '<a>Click</a>'
sanitize('<a href="https://safe.com">Click</a>')  // '<a href="https://safe.com">Click</a>'
```

**Removes Dangerous Tags:**
```typescript
sanitize('<iframe src="http://evil.com"></iframe>')  // ''
sanitize('<object data="evil.swf"></object>')  // ''
sanitize('<style>body{background:url("javascript:alert(1)")}</style>')  // ''
```

## API

### `sanitize(html, options?)`

Sanitize an HTML string with optional configuration.

```typescript
import { sanitize } from '@lpm.dev/neo.sanitize'

const result = sanitize('<p>Hello</p>', {
  allowedTags: ['p', 'strong', 'em'],
  allowedAttributes: {
    a: ['href', 'title'],
    img: ['src', 'alt']
  },
  allowedProtocols: ['http', 'https', 'mailto']
})
```

**Parameters:**
- `html` (string) - HTML string to sanitize
- `options` (object, optional) - Sanitization options

**Returns:** Sanitized HTML string (default) or DocumentFragment

### Predefined Schemas

#### `sanitizeBasic(html)`

Minimal HTML - text formatting, links, and lists only.

```typescript
import { sanitizeBasic } from '@lpm.dev/neo.sanitize'

sanitizeBasic('<p><strong>Bold</strong> text</p>')
// Output: '<p><strong>Bold</strong> text</p>'

sanitizeBasic('<img src="image.jpg">')
// Output: '' (images not allowed in BASIC)
```

**Allowed Tags:** p, strong, em, b, i, u, a, ul, ol, li, br, hr

#### `sanitizeRelaxed(html)`

Rich HTML - includes images, tables, headings, and class attributes.

```typescript
import { sanitizeRelaxed } from '@lpm.dev/neo.sanitize'

sanitizeRelaxed('<img src="image.jpg" alt="Photo">')
// Output: '<img src="image.jpg" alt="Photo">'

sanitizeRelaxed('<table><tr><td>Data</td></tr></table>')
// Output: '<table><tbody><tr><td>Data</td></tr></tbody></table>'
```

**Allowed Tags:** All BASIC tags + img, h1-h6, div, span, table, thead, tbody, tr, th, td, blockquote, pre, code

**Allowed Attributes:** All BASIC attributes + class, id, style (on specific tags)

#### `sanitizeStrict(html)`

Text only - strips all HTML tags.

```typescript
import { sanitizeStrict } from '@lpm.dev/neo.sanitize'

sanitizeStrict('<p>Just <strong>text</strong> content</p>')
// Output: 'Just text content'

sanitizeStrict('<script>alert(1)</script><p>Safe</p>')
// Output: 'Safe'
```

### `createSanitizer(options)`

Create a reusable sanitizer instance with preset configuration.

```typescript
import { createSanitizer } from '@lpm.dev/neo.sanitize'

const sanitizer = createSanitizer({
  allowedTags: ['p', 'strong', 'em', 'a'],
  allowedAttributes: {
    a: ['href', 'title']
  }
})

// Reuse the same configuration
const result1 = sanitizer.sanitize('<p>Hello</p>')
const result2 = sanitizer.sanitize('<a href="/">Link</a>')

// Get current config
const config = sanitizer.getConfig()

// Update config
sanitizer.updateConfig({ allowDataAttributes: true })
```

## Configuration Options

```typescript
interface SanitizeOptions {
  // Tag and attribute filtering
  allowedTags?: string[]  // Default: 50+ safe HTML tags
  allowedAttributes?: Record<string, string[]>  // Tag-specific attributes
  forbiddenAttributes?: string[]  // Default: 60+ event handlers

  // Protocol filtering
  allowedProtocols?: string[]  // Default: ['http', 'https', 'mailto', 'tel', 'ftp', 'ftps']

  // Special attributes
  allowDataAttributes?: boolean  // Allow data-* attributes
  allowAriaAttributes?: boolean  // Allow aria-* attributes
  allowClassAttribute?: boolean  // Allow class attribute
  allowIdAttribute?: boolean  // Allow id attribute
  allowStyleAttribute?: boolean  // Allow style attribute
  allowAllAttributes?: boolean  // Allow all attributes (dangerous!)

  // Content handling
  keepTextContent?: boolean  // Keep text from removed tags (safe tags only)
  stripTags?: boolean  // Remove tags but keep text content

  // Output format
  returnString?: boolean  // Return string (default: true) or DocumentFragment

  // Normalization
  lowercaseTags?: boolean  // Normalize tag names to lowercase
  lowercaseAttributes?: boolean  // Normalize attribute names to lowercase
}
```

## Examples

### Blog Comment Sanitization

```typescript
import { sanitize } from '@lpm.dev/neo.sanitize'

// Allow rich text formatting but no images or scripts
const cleanComment = sanitize(userComment, {
  allowedTags: ['p', 'strong', 'em', 'a', 'ul', 'ol', 'li', 'br'],
  allowedAttributes: {
    a: ['href', 'title']
  },
  allowedProtocols: ['http', 'https']
})
```

### Markdown-to-HTML Output

```typescript
import { sanitizeRelaxed } from '@lpm.dev/neo.sanitize'

// Sanitize generated HTML from markdown
const html = markdownToHtml(userMarkdown)
const safe = sanitizeRelaxed(html)  // Allow tables, code blocks, etc.
```

### Email Content Sanitization

```typescript
import { sanitize } from '@lpm.dev/neo.sanitize'

// Very restrictive - no links, images, or scripts
const cleanEmail = sanitize(emailBody, {
  allowedTags: ['p', 'strong', 'em', 'br'],
  allowedAttributes: {},
  keepTextContent: true
})
```

### Custom Configuration

```typescript
import { sanitize } from '@lpm.dev/neo.sanitize'

// Allow specific tags and attributes for your use case
const result = sanitize(html, {
  allowedTags: ['div', 'p', 'img', 'a'],
  allowedAttributes: {
    div: ['class'],
    p: ['class'],
    img: ['src', 'alt', 'class'],
    a: ['href', 'title', 'class']
  },
  allowDataAttributes: true,  // Allow data-* attributes
  allowAriaAttributes: true,  // Allow aria-* attributes
  allowedProtocols: ['http', 'https'],
  keepTextContent: false  // Remove content from disallowed tags
})
```

### DocumentFragment Output

```typescript
import { sanitize } from '@lpm.dev/neo.sanitize'

// Get DocumentFragment instead of string (for DOM manipulation)
const fragment = sanitize(html, { returnString: false }) as DocumentFragment

// Append to DOM
document.body.appendChild(fragment)
```

## Performance

Benchmarks run on Node.js with jsdom, comparing against industry-standard libraries:

### Small HTML (~50 chars)
- **sanitize-html:** 83,253 ops/sec (fastest) ⚡
- **DOMPurify:** 14,145 ops/sec
- **neo.sanitize:** 8,195 ops/sec

### Medium HTML (~300 chars)
- **sanitize-html:** 40,285 ops/sec (fastest) ⚡
- **DOMPurify:** 3,750 ops/sec
- **neo.sanitize:** 2,373 ops/sec

### Large HTML (~1.5 KB)
- **sanitize-html:** 18,052 ops/sec (fastest) ⚡
- **neo.sanitize:** 1,431 ops/sec
- **DOMPurify:** 1,277 ops/sec

### HTML with XSS Vectors
- **sanitize-html:** 81,844 ops/sec (fastest) ⚡
- **DOMPurify:** 9,463 ops/sec
- **neo.sanitize:** 6,235 ops/sec

### High-Volume (1000 small HTML)
- **sanitize-html:** 119 ops/sec (fastest) ⚡
- **DOMPurify:** 13 ops/sec
- **neo.sanitize:** 11 ops/sec

**Note:** Phase 1 focuses on security and correctness. Performance optimizations are planned for Phase 2 and 3. sanitize-html is server-side only (uses htmlparser2), while neo.sanitize and DOMPurify are browser-compatible.

## Browser Compatibility

- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+
- ✅ Node.js 18+ (with jsdom)

**Requirements:**
- DOMParser API
- DocumentFragment API
- ES2020+ features

## Security Guarantees

### What We Block

✅ **Script Tags** - `<script>`, `<iframe>`, `<object>`, `<embed>`, `<applet>`
✅ **Event Handlers** - `onclick`, `onerror`, `onload`, and 60+ more
✅ **Dangerous Protocols** - `javascript:`, `data:`, `vbscript:`, `file:`, `about:`
✅ **Style Injection** - `<style>` tags and CSS expressions
✅ **Meta Redirects** - `<meta http-equiv="refresh">`
✅ **Base Hijacking** - `<base>` tags
✅ **Link Injection** - `<link>` tags
✅ **Form Tags** - `<form>`, `<input>`, `<button>` (unless explicitly allowed)

### What We Allow (Default)

✅ **Text Formatting** - `<p>`, `<strong>`, `<em>`, `<b>`, `<i>`, `<u>`
✅ **Headings** - `<h1>` through `<h6>`
✅ **Lists** - `<ul>`, `<ol>`, `<li>`
✅ **Links** - `<a href="...">` (safe protocols only)
✅ **Images** - `<img src="...">` (safe protocols only)
✅ **Tables** - `<table>`, `<tr>`, `<td>`, `<th>`
✅ **Code** - `<pre>`, `<code>`
✅ **Quotes** - `<blockquote>`
✅ **Divisions** - `<div>`, `<span>`

## Testing

143 comprehensive test cases covering OWASP XSS vectors:

- ✅ 25 Script injection tests
- ✅ 40 Event handler tests
- ✅ 37 Protocol handler tests
- ✅ 41 Basic vectors and edge cases

```bash
# Run tests
npm test

# Run benchmarks
npm run bench

# Type check
npm run typecheck

# Build
npm run build
```

## Migration from DOMPurify

```typescript
// Before (DOMPurify)
import DOMPurify from 'dompurify'

const clean = DOMPurify.sanitize(dirty, {
  ALLOWED_TAGS: ['p', 'strong'],
  ALLOWED_ATTR: ['href']
})

// After (neo.sanitize)
import { sanitize } from '@lpm.dev/neo.sanitize'

const clean = sanitize(dirty, {
  allowedTags: ['p', 'strong'],
  allowedAttributes: {
    a: ['href']
  }
})
```

## Migration from sanitize-html

```typescript
// Before (sanitize-html)
import sanitizeHtml from 'sanitize-html'

const clean = sanitizeHtml(dirty, {
  allowedTags: ['p', 'strong'],
  allowedAttributes: {
    a: ['href']
  }
})

// After (neo.sanitize) - same API!
import { sanitize } from '@lpm.dev/neo.sanitize'

const clean = sanitize(dirty, {
  allowedTags: ['p', 'strong'],
  allowedAttributes: {
    a: ['href']
  }
})
```

## TypeScript Support

Full TypeScript support with strict type checking:

```typescript
import { sanitize, SanitizeOptions } from '@lpm.dev/neo.sanitize'

const options: SanitizeOptions = {
  allowedTags: ['p', 'strong'],
  allowedAttributes: {
    a: ['href', 'title']
  }
}

const clean: string = sanitize(html, options)
```

## Tree-Shaking

Import only what you need for optimal bundle size:

```typescript
// Import specific functions (< 1 KB)
import { sanitize } from '@lpm.dev/neo.sanitize'

// Import schema helpers (< 500 bytes each)
import { sanitizeBasic, sanitizeRelaxed, sanitizeStrict } from '@lpm.dev/neo.sanitize'

// Import core utilities
import { createSanitizer } from '@lpm.dev/neo.sanitize'
```

## Why neo.sanitize?

### vs DOMPurify
- ✅ **Zero dependencies** (DOMPurify has none too)
- ✅ **Tree-shakeable** exports
- ✅ **TypeScript-first** (DOMPurify has community types)
- ✅ **Predefined schemas** for common use cases
- ✅ **Simpler API** for most use cases
- ⚠️ Less mature (DOMPurify is battle-tested)

### vs sanitize-html
- ✅ **Browser-native** (sanitize-html is server-only)
- ✅ **Zero dependencies** (sanitize-html has 4 dependencies)
- ✅ **Smaller bundle** (< 3 KB vs ~60 KB)
- ✅ **TypeScript-first** (sanitize-html has community types)
- ⚠️ Slower performance (sanitize-html uses htmlparser2)

## Development Status

**Phase 1 (Current): Browser-Native MVP** ✅
- [x] Zero dependencies (native DOMParser)
- [x] Tag/attribute whitelisting
- [x] Protocol validation
- [x] Event handler removal
- [x] Predefined schemas (BASIC, RELAXED, STRICT)
- [x] 143 XSS vector tests (100% passing)
- [x] Benchmarks vs DOMPurify and sanitize-html
- [x] Comprehensive documentation

**Phase 2 (Planned): Performance Optimization**
- [ ] Caching and memoization
- [ ] Optimized attribute validation
- [ ] String-based parsing option
- [ ] Target: 2-3x performance improvement

**Phase 3 (Planned): Advanced Features**
- [ ] Custom element support
- [ ] CSS sanitization
- [ ] SVG sanitization
- [ ] URL rewriting hooks
- [ ] Sanitization hooks and plugins

## License

MIT
