# @lpm.dev/neo.sanitize

**Browser-native HTML sanitization with zero dependencies**

Fast, secure, and lightweight HTML sanitization library that prevents XSS attacks using the browser's native DOMParser. No runtime dependencies, tree-shakeable, and TypeScript-first.

## Features

✅ **Zero Dependencies** - Uses native browser DOMParser
✅ **Secure by Default** - Removes tested script, protocol, CSS, clobbering, and mutation-XSS patterns
✅ **Tree-Shakeable** - Import only what you need
✅ **TypeScript-First** - Full type safety with strict mode
✅ **Predefined Schemas** - BASIC, RELAXED, STRICT configurations
✅ **Customizable** - Fine-grained control over tags, attributes, and protocols
✅ **Cross-Realm Safe** - Supports browser realms and explicit DOM runtimes
✅ **Bundle Budget** - The ESM entry must stay within 15 KB gzipped

## Installation

```bash
lpm install @lpm.dev/neo.sanitize
```

## Quick Start

```typescript
import { sanitize } from "@lpm.dev/neo.sanitize";

// Basic usage - sanitize HTML string
const clean = sanitize("<p>Hello <strong>world</strong>!</p>");
// Output: '<p>Hello <strong>world</strong>!</p>'

// Removes dangerous content
const safe = sanitize(
  '<p onclick="alert(1)">Click</p><script>alert(1)</script>',
);
// Output: '<p>Click</p>'
```

## Security Features

### XSS Protection

**Blocks Script Injection:**

```typescript
sanitize('<script>alert("XSS")</script>'); // ''
sanitize("<p>Safe</p><script>alert(1)</script>"); // '<p>Safe</p>'
```

**Removes Event Handlers:**

```typescript
sanitize('<div onclick="alert(1)">Click</div>'); // '<div>Click</div>'
sanitize('<img src=x onerror="alert(1)">'); // '<img src="x">'
```

**Validates URL Protocols:**

```typescript
sanitize('<a href="javascript:alert(1)">Click</a>'); // '<a>Click</a>'
sanitize('<a href="https://safe.com">Click</a>'); // '<a href="https://safe.com">Click</a>'
```

**Removes Dangerous Tags:**

```typescript
sanitize('<iframe src="http://evil.com"></iframe>'); // ''
sanitize('<object data="evil.swf"></object>'); // ''
sanitize('<style>body{background:url("javascript:alert(1)")}</style>'); // ''
```

## API

### `sanitize(html, options?, runtime?)`

Sanitize an HTML string with optional configuration.

```typescript
import { sanitize } from "@lpm.dev/neo.sanitize";

const result = sanitize("<p>Hello</p>", {
  allowedTags: ["p", "strong", "em"],
  allowedAttributes: {
    a: ["href", "title"],
    img: ["src", "alt"],
  },
  allowedProtocols: ["http", "https", "mailto"],
});
```

**Parameters:**

- `html` (string) - HTML string to sanitize
- `options` (object, optional) - Sanitization options
- `runtime` (object, optional) - DOM runtime for Node.js or a Web Worker

**Returns:** Sanitized HTML string (default) or DocumentFragment

### Predefined Schemas

#### `sanitizeBasic(html)`

Minimal HTML - text formatting, links, and lists only.

```typescript
import { sanitizeBasic } from "@lpm.dev/neo.sanitize";

sanitizeBasic("<p><strong>Bold</strong> text</p>");
// Output: '<p><strong>Bold</strong> text</p>'

sanitizeBasic('<img src="image.jpg">');
// Output: '' (images not allowed in BASIC)
```

**Allowed Tags:** p, strong, em, b, i, u, a, ul, ol, li, br, hr

#### `sanitizeRelaxed(html)`

Rich HTML - includes images, tables, headings, and class attributes.

```typescript
import { sanitizeRelaxed } from "@lpm.dev/neo.sanitize";

sanitizeRelaxed('<img src="image.jpg" alt="Photo">');
// Output: '<img src="image.jpg" alt="Photo">'

sanitizeRelaxed("<table><tr><td>Data</td></tr></table>");
// Output: '<table><tbody><tr><td>Data</td></tr></tbody></table>'
```

**Allowed Tags:** All BASIC tags + img, h1-h6, div, span, table, thead, tbody, tr, th, td, blockquote, pre, code

**Allowed Attributes:** All BASIC attributes + class, id, style (on specific tags)

#### `sanitizeStrict(html)`

Text only - strips all HTML tags.

```typescript
import { sanitizeStrict } from "@lpm.dev/neo.sanitize";

sanitizeStrict("<p>Just <strong>text</strong> content</p>");
// Output: 'Just text content'

sanitizeStrict("<script>alert(1)</script><p>Safe</p>");
// Output: 'Safe'
```

### `createSanitizer(options, runtime?)`

Create a reusable sanitizer instance with preset configuration.

```typescript
import { createSanitizer } from "@lpm.dev/neo.sanitize";

const sanitizer = createSanitizer({
  allowedTags: ["p", "strong", "em", "a"],
  allowedAttributes: {
    a: ["href", "title"],
  },
});

// Reuse the same configuration
const result1 = sanitizer.sanitize("<p>Hello</p>");
const result2 = sanitizer.sanitize('<a href="/">Link</a>');

// Get a detached, frozen configuration snapshot
const config = sanitizer.getConfig();

// Update config
sanitizer.updateConfig({ allowDataAttributes: true });
```

`getConfig()` returns a detached, frozen snapshot. `updateConfig()` replaces the internal configuration without changing earlier snapshots.

### Node.js and Web Workers

Node.js does not include the required DOM APIs. Install a DOM implementation and pass its runtime explicitly.

```typescript
import { JSDOM } from "jsdom";
import { sanitize } from "@lpm.dev/neo.sanitize";

const dom = new JSDOM("");
const runtime = {
  document: dom.window.document,
  DOMParser: dom.window.DOMParser,
};

const clean = sanitize(dirtyHtml, {}, runtime);
```

Web Workers must also supply `{ document, DOMParser }`. The two APIs must come from the same compatible DOM implementation.

Pass the runtime as the second argument to a preset helper. Pass it to `parseHTML` as the second argument.

The `createSanitizer` function stores its runtime. Each call to its `sanitize` method uses that runtime.

## Configuration Options

```typescript
interface SanitizeOptions {
  // Tag and attribute filtering
  allowedTags?: string[]; // Default: 50+ safe HTML tags. Active tags always stay blocked.
  allowedAttributes?: Record<string, string[]>; // Tag-specific attributes
  forbiddenAttributes?: string[]; // Default: 60+ event handlers

  // Protocol filtering
  allowedProtocols?: string[]; // Default: ['http', 'https', 'mailto', 'tel', 'ftp', 'ftps']

  // Special attributes
  allowDataAttributes?: boolean; // Allow data-* attributes
  allowAriaAttributes?: boolean; // Allow aria-* attributes
  allowClassAttribute?: boolean; // Allow class attribute
  allowIdAttribute?: boolean; // Allow id attribute
  allowStyleAttribute?: boolean; // Allow style attribute
  allowAllAttributes?: string[]; // Tags that accept attributes outside the per-tag list

  // Content handling
  keepTextContent?: boolean; // Unwrap safe removed elements and keep sanitized children
  stripTags?: boolean; // Remove all wrappers and keep sanitized children

  // Output format
  returnString?: boolean; // Return string (default: true) or DocumentFragment

  // Normalization
  lowercaseTags?: boolean; // Normalize tag names to lowercase
  lowercaseAttributes?: boolean; // Normalize attribute names to lowercase

  // Experimental mutation-XSS defenses
  detectMXSS?: boolean; // Remove foreign namespaces and require stable output
}
```

## Examples

### Blog Comment Sanitization

```typescript
import { sanitize } from "@lpm.dev/neo.sanitize";

// Allow rich text formatting but no images or scripts
const cleanComment = sanitize(userComment, {
  allowedTags: ["p", "strong", "em", "a", "ul", "ol", "li", "br"],
  allowedAttributes: {
    a: ["href", "title"],
  },
  allowedProtocols: ["http", "https"],
});
```

### Markdown-to-HTML Output

```typescript
import { sanitizeRelaxed } from "@lpm.dev/neo.sanitize";

// Sanitize generated HTML from markdown
const html = markdownToHtml(userMarkdown);
const safe = sanitizeRelaxed(html); // Allow tables, code blocks, etc.
```

### Email Content Sanitization

```typescript
import { sanitize } from "@lpm.dev/neo.sanitize";

// Very restrictive - no links, images, or scripts
const cleanEmail = sanitize(emailBody, {
  allowedTags: ["p", "strong", "em", "br"],
  allowedAttributes: {},
  keepTextContent: true,
});
```

### Custom Configuration

```typescript
import { sanitize } from "@lpm.dev/neo.sanitize";

// Allow specific tags and attributes for your use case
const result = sanitize(html, {
  allowedTags: ["div", "p", "img", "a"],
  allowedAttributes: {
    div: ["class"],
    p: ["class"],
    img: ["src", "alt", "class"],
    a: ["href", "title", "class"],
  },
  allowDataAttributes: true, // Allow data-* attributes
  allowAriaAttributes: true, // Allow aria-* attributes
  allowedProtocols: ["http", "https"],
  keepTextContent: false, // Remove content from disallowed tags
});
```

### DocumentFragment Output

```typescript
import { sanitize } from "@lpm.dev/neo.sanitize";

// Get DocumentFragment instead of string (for DOM manipulation)
const fragment = sanitize(html, { returnString: false }) as DocumentFragment;

// Append to DOM
document.body.appendChild(fragment);
```

## Performance

The sanitizer caches resolved configuration, compiled policy lookups, and DOM parsers. Hook-free paths also avoid temporary arrays and unnecessary fragment cloning.

Local paired-build measurements used Node.js with jsdom. They showed these throughput changes against the previous build:

| Input | Throughput change |
| --- | ---: |
| Small HTML | approximately 83% higher |
| Medium HTML | approximately 167% higher |
| HTML with XSS vectors | approximately 73% higher |
| Large HTML | approximately 66% higher |

These measurements are environment-specific and are not performance guarantees. Run `lpm run bench` in the target environment before making capacity decisions.

For repeated calls with the same configuration, use `createSanitizer()`. It reuses the compiled configuration and policy sets.

## Browser Compatibility

- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+
- ✅ Node.js 18+ (with an explicit DOM runtime)
- ✅ Web Workers (with an explicit DOM runtime)

**Requirements:**

- DOMParser API
- DocumentFragment API
- ES2020+ features

The package has no runtime dependency on jsdom. Applications select and install their DOM implementation.

## Experimental mXSS Defense

Set `detectMXSS: true` to enable the experimental mutation-XSS defense.

This mode removes SVG, MathML, and all other foreign namespaces. It then sanitizes each reparsed result without hooks.

The sanitizer runs a maximum of three stability passes. If serialization does not become stable, it returns empty output.

This option can change before the next major release. When sanitized output must contain SVG or MathML, do not use this mode.

## Hook Safety

The sanitizer calls each configured hook once. Hooks can inspect or change the DOM during the first sanitization pass.

After `afterSanitize`, a hook-free pass checks every current element and attribute. Hook output cannot bypass the configured policy.

## Security Guarantees

### What We Block

✅ **Script Tags** - `<script>`, `<iframe>`, `<object>`, `<embed>`, `<applet>`
✅ **Event Handlers** - `onclick`, `onerror`, `onload`, and 60+ more
✅ **Dangerous Protocols** - `javascript:`, `data:`, `vbscript:`, `file:`, `about:`
✅ **Style Injection** - `<style>` tags and CSS expressions
✅ **Meta Redirects** - `<meta http-equiv="refresh">`
✅ **Base Hijacking** - `<base>` tags
✅ **Link Injection** - `<link>` tags
✅ **Form Tags** - `<form>`, `<input>`, `<button>`

The `allowedTags` option cannot enable active-content tags. This rule also applies to custom schemas.

URL-list attributes use per-candidate protocol checks. These attributes include `srcset`, `imagesrcset`, `ping`, and `attributionsrc`.

Strict CSS mode allows listed properties only. It also removes URL and dynamic CSS functions.

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

The suite contains 509 automated tests across 14 files. It covers sanitizer behavior, public configuration, hooks, runtimes, and XSS regression vectors.

Coverage must stay at or above 90% for statements, functions, and lines. Branch coverage must stay at or above 80%.

```bash
# Run tests
lpm run test

# Run tests with coverage gates
lpm run test:coverage

# Run all checks required before publication
lpm run release:check

# Run benchmarks
lpm run bench

# Type check
lpm run typecheck

# Build
lpm run build
```

## Migration from DOMPurify

```typescript
// Before (DOMPurify)
import DOMPurify from "dompurify";

const clean = DOMPurify.sanitize(dirty, {
  ALLOWED_TAGS: ["p", "strong"],
  ALLOWED_ATTR: ["href"],
});

// After (neo.sanitize)
import { sanitize } from "@lpm.dev/neo.sanitize";

const clean = sanitize(dirty, {
  allowedTags: ["p", "strong"],
  allowedAttributes: {
    a: ["href"],
  },
});
```

## Migration from sanitize-html

```typescript
// Before (sanitize-html)
import sanitizeHtml from "sanitize-html";

const clean = sanitizeHtml(dirty, {
  allowedTags: ["p", "strong"],
  allowedAttributes: {
    a: ["href"],
  },
});

// After (neo.sanitize) - same API!
import { sanitize } from "@lpm.dev/neo.sanitize";

const clean = sanitize(dirty, {
  allowedTags: ["p", "strong"],
  allowedAttributes: {
    a: ["href"],
  },
});
```

## TypeScript Support

Full TypeScript support with strict type checking:

```typescript
import { sanitize, SanitizeOptions } from "@lpm.dev/neo.sanitize";

const options: SanitizeOptions = {
  allowedTags: ["p", "strong"],
  allowedAttributes: {
    a: ["href", "title"],
  },
};

const clean: string = sanitize(html, options);
```

## Tree-Shaking

Import only what you need for optimal bundle size:

```typescript
// Import a specific public function
import { sanitize } from "@lpm.dev/neo.sanitize";

// Import schema helpers
import {
  sanitizeBasic,
  sanitizeRelaxed,
  sanitizeStrict,
} from "@lpm.dev/neo.sanitize";

// Import core utilities
import { createSanitizer } from "@lpm.dev/neo.sanitize";
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
- ✅ **No runtime dependencies** and a 15 KB gzip budget for the ESM entry
- ✅ **TypeScript-first** (sanitize-html has community types)
- ⚠️ Slower performance (sanitize-html uses htmlparser2)

## License

[MIT](LICENSE)

Report vulnerabilities privately. Read the [security policy](SECURITY.md) for the reporting procedure.
