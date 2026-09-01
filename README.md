# @lpm.dev/neo.sanitize

`@lpm.dev/neo.sanitize` removes disallowed HTML content with browser DOM APIs or
an explicit DOM runtime.

## Features

- **HTML policies:** Supports allowed tags, attributes, protocols, and insertion
  contexts.
- **Preset policies:** Provides basic, relaxed, and text-only sanitization.
- **Trusted Types:** Creates `TrustedHTML` for browser sinks that enforce
  Trusted Types.
- **Resource limits:** The package limits input length, DOM nodes, and DOM
  depth.
- **Runtime control:** Uses browser globals or an explicit DOM runtime for
  Node.js and Web Workers.
- **Dependency surface:** The package has no runtime dependencies.
- **Bundle budget:** The main ESM entry must remain at or below 15 KB gzip.

## Install

Install the package with LPM:

```bash
lpm install @lpm.dev/neo.sanitize
```

## Quick start

```typescript
import { sanitize } from "@lpm.dev/neo.sanitize";

const clean = sanitize("<p>Hello <strong>world</strong>!</p>");
// "<p>Hello <strong>world</strong>!</p>"

const safe = sanitize(
  '<p onclick="alert(1)">Click</p><script>alert(1)</script>',
);
// "<p>Click</p>"
```

## API

### `sanitize(html, options?, runtime?)`

`sanitize()` applies an HTML policy to a string.

**Parameters**

| Name      | Type              | Default         | Description                                          |
| --------- | ----------------- | --------------- | ---------------------------------------------------- |
| `html`    | `string`          | Required        | The HTML string to sanitize.                         |
| `options` | `SanitizeOptions` | `{}`            | The HTML policy and resource limits.                 |
| `runtime` | `DOMRuntime`      | Browser globals | The document and parser for an explicit DOM runtime. |

**Returns:** `string | DocumentFragment` — A string by default. If
`returnString` is `false`, the function returns a fragment.

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

### `sanitizeToTrustedHTML(html, policy, options?, runtime?)`

`sanitizeToTrustedHTML()` returns the exact `TrustedHTML` type from the supplied
policy.

```typescript
import { sanitizeToTrustedHTML } from "@lpm.dev/neo.sanitize";

const policy = trustedTypes.createPolicy("neo-sanitize", {
  createHTML(input) {
    return input;
  },
});

const clean = sanitizeToTrustedHTML(dirtyHtml, policy, {
  detectMXSS: true,
});

target.innerHTML = clean;
```

The policy must return its input without changes. The sanitizer uses the policy
for inert parser sinks and the final result.

Keep this policy private to the sanitizer integration. Direct policy use can
bypass HTML sanitization.

For an explicit browser runtime, create the policy in that runtime's realm.

If Trusted Types are unavailable, the function throws. It rejects
`returnString: false` because `TrustedHTML` is a string-sink type.

### `SANITIZER_VERSION`

`SANITIZER_VERSION` contains the package version for logs, security reports, and
runtime diagnostics.

```typescript
import { SANITIZER_VERSION } from "@lpm.dev/neo.sanitize";
```

### Preset policies

#### `sanitizeBasic(html)`

`sanitizeBasic()` permits text formatting, links, and lists.

```typescript
import { sanitizeBasic } from "@lpm.dev/neo.sanitize";

sanitizeBasic("<p><strong>Bold</strong> text</p>");
// "<p><strong>Bold</strong> text</p>"

sanitizeBasic('<img src="image.jpg">');
// ""
```

Allowed tags are `p`, `br`, `span`, `strong`, `b`, `em`, `i`, `u`, `s`, `del`,
`code`, `pre`, `ul`, `ol`, `li`, and `a`.

#### `sanitizeRelaxed(html)`

`sanitizeRelaxed()` also permits images, tables, headings, class attributes, and
more formatting elements.

```typescript
import { sanitizeRelaxed } from "@lpm.dev/neo.sanitize";

sanitizeRelaxed('<img src="image.jpg" alt="Photo">');
// '<img src="image.jpg" alt="Photo">'

sanitizeRelaxed("<table><tr><td>Data</td></tr></table>");
// "<table><tbody><tr><td>Data</td></tr></tbody></table>"
```

This policy includes all `DEFAULT_ALLOWED_TAGS`. It permits default link, image,
table, quote, time, and code attributes.

The policy also permits `class` and `data-*` attributes. It does not permit `id`
or `style` attributes.

#### `sanitizeStrict(html)`

`sanitizeStrict()` removes all HTML tags and returns text.

```typescript
import { sanitizeStrict } from "@lpm.dev/neo.sanitize";

sanitizeStrict("<p>Just <strong>text</strong> content</p>");
// "Just text content"

sanitizeStrict("<script>alert(1)</script><p>Safe</p>");
// "Safe"
```

### `createSanitizer(options, runtime?)`

`createSanitizer()` creates a reusable sanitizer with preset options and an
optional runtime.

```typescript
import { createSanitizer } from "@lpm.dev/neo.sanitize";

const sanitizer = createSanitizer({
  allowedTags: ["p", "strong", "em", "a"],
  allowedAttributes: {
    a: ["href", "title"],
  },
});

const first = sanitizer.sanitize("<p>Hello</p>");
const second = sanitizer.sanitize('<a href="/">Link</a>');

const options = sanitizer.getConfig();
sanitizer.updateConfig({ allowDataAttributes: true });
```

`getConfig()` returns a detached, frozen snapshot. `updateConfig()` does not
change earlier snapshots.

### `compileSanitizeOptions(options?)`

`compileSanitizeOptions()` validates and freezes options, then compiles the
policy lookup sets.

```typescript
import { compileSanitizeOptions, sanitize } from "@lpm.dev/neo.sanitize";

const options = compileSanitizeOptions({
  allowedTags: ["p", "strong", "a"],
  allowedAttributes: { a: ["href"] },
});

const first = sanitize(firstHtml, options, firstRuntime);
const second = sanitize(secondHtml, options, secondRuntime);
```

The function does not accept hooks. If hooks are necessary or the runtime
remains the same, use `createSanitizer()`.

### Explicit DOM runtimes

Node.js does not include the required DOM APIs. Install a DOM implementation and
provide its runtime.

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

Web Workers must also provide `{ document, DOMParser }`. Both APIs must come
from the same compatible DOM implementation.

Pass the runtime as the second argument to a preset helper. Pass it to
`parseHTML()` as the second argument.

Pass an insertion context as the third argument to `parseHTML()`. A sanitizer
from `createSanitizer()` uses its stored runtime.

### `SanitizeOptions`

```typescript
interface SanitizeOptions {
  // Tag and attribute filtering
  // Default: More than 50 safe HTML tags. Active tags remain blocked.
  allowedTags?: readonly string[];
  // Tag-specific attributes
  allowedAttributes?: Readonly<Record<string, readonly string[]>>;
  // Default: More than 60 event-handler attributes
  forbiddenAttributes?: readonly string[];
  // Default: ["http", "https", "mailto", "tel", "ftp", "ftps"]
  allowedProtocols?: readonly string[];

  // Special attributes and elements
  allowDataAttributes?: boolean;
  allowAriaAttributes?: boolean;
  allowClassAttribute?: boolean;
  allowIdAttribute?: boolean;
  allowStyleAttribute?: boolean;
  allowCustomElements?: boolean;
  // Tags that accept attributes outside their tag-specific lists
  allowAllAttributes?: readonly string[];

  // Content handling
  keepTextContent?: boolean;
  stripTags?: boolean;

  // Output format
  returnString?: boolean;
  insertionContext?: HTMLInsertionContext;

  // Resource limits
  maxInputLength?: number;
  maxDOMNodes?: number;
  maxDOMDepth?: number;

  // Deprecated compatibility options
  lowercaseTags?: boolean;
  lowercaseAttributes?: boolean;

  // Security options
  preventDOMClobbering?: boolean;
  strictCSSValidation?: boolean;
  detectMXSS?: boolean;
}
```

`lowercaseTags` and `lowercaseAttributes` are deprecated compatibility options.
The HTML parser always canonicalizes names.

`preventDOMClobbering` removes all `id` and `name` attributes.
`strictCSSValidation` filters XSS and resource-loading patterns, not layout
behavior.

`keepTextContent` unwraps a removed safe element and keeps its sanitized
children. `stripTags` removes all wrappers and keeps sanitized children.

### Insertion contexts

HTML parsing depends on the element that receives the output. Set
`insertionContext` for a table or select element.

```typescript
const cleanRows = sanitize(userRows, {
  insertionContext: "tbody",
});

tableBody.innerHTML = cleanRows;
```

The package supports these contexts:

`body`, `div`, `table`, `caption`, `colgroup`, `thead`, `tbody`, `tfoot`, `tr`,
`td`, `th`, `select`, `optgroup`, and `option`.

The default context is `body`. The package rejects raw-text, script, style,
template, and foreign-namespace contexts.

The configured context must match the output element. Do not sanitize for `body`
and insert the result into a table context.

## Behavior and limits

- The default input limit is `200000` UTF-16 code units.
- The default node limit is `100000` visited DOM nodes per pass.
- The default depth limit is `1024` source elements.
- If an input exceeds a limit, the package returns an empty string or fragment.
- The package runs a bounded HTML-state depth preflight before DOM parsing.

Set `detectMXSS: true` to enable the experimental mutation-XSS defense. This
mode requires stable output after reparsing.

The package runs at most three stability passes. If serialization does not
become stable, it returns empty output.

This option can change before the next major release. If output must contain SVG
or MathML, use a namespace-aware sanitizer.

`beforeSanitize` runs once for each in-limit string. Element and attribute hooks
run once for each allowed value that they receive.

`afterSanitize` runs once after a DOM sanitization pass. Inputs that fail length
or depth limits do not reach DOM hooks.

After `afterSanitize`, a hook-free pass checks all current elements and
attributes. Hook output cannot bypass the configured policy.

## Security

`@lpm.dev/neo.sanitize` applies an HTML policy. The application remains
responsible for the insertion context and surrounding security controls.

- Active tags remain blocked, including tags in `allowedTags`.
- HTML policies cannot enable SVG, MathML, or another foreign namespace.
- The default policy rejects custom elements and customized built-ins.
- URL-list attributes receive per-candidate protocol checks.
- Strict CSS mode removes URL and dynamic CSS functions.
- The default policy does not permit `id` or `style` attributes.

Blocked active tags include `script`, `iframe`, `object`, `embed`, `applet`,
`style`, `meta`, `base`, `link`, and form controls.

Blocked protocols include `javascript:`, `data:`, `vbscript:`, `file:`, and
`about:`. The policy also removes event-handler attributes.

WARNING: Do not enable `allowCustomElements` for attacker-controlled HTML.
Custom elements can run application lifecycle code after insertion.

Strict CSS mode does not isolate layout. It permits properties that can
reposition content or cover page content.

Leave `allowStyleAttribute` disabled for untrusted content unless the
application provides separate layout isolation.

Read [SECURITY.md](./SECURITY.md) before you use the package at a security
boundary.

Report vulnerabilities privately with the procedure in
[SECURITY.md](./SECURITY.md).

## Examples

### Sanitize a blog comment

```typescript
import { sanitize } from "@lpm.dev/neo.sanitize";

const cleanComment = sanitize(userComment, {
  allowedTags: ["p", "strong", "em", "a", "ul", "ol", "li", "br"],
  allowedAttributes: {
    a: ["href", "title"],
  },
  allowedProtocols: ["http", "https"],
});
```

### Return a fragment

```typescript
import { sanitize } from "@lpm.dev/neo.sanitize";

const fragment = sanitize(html, {
  returnString: false,
}) as DocumentFragment;

document.body.appendChild(fragment);
```

## Migration from `DOMPurify`

The option names and policy behavior differ. Map each option and run application
security tests after the migration.

```diff
- import DOMPurify from "dompurify";
+ import { sanitize } from "@lpm.dev/neo.sanitize";
```

```typescript
const clean = sanitize(dirty, {
  allowedTags: ["p", "strong"],
  allowedAttributes: {
    a: ["href"],
  },
});
```

## Migration from `sanitize-html`

The packages share some option names, but they do not have identical policies or
runtime requirements.

```diff
- import sanitizeHtml from "sanitize-html";
+ import { sanitize } from "@lpm.dev/neo.sanitize";
```

Run application security tests after the migration.

## Performance

The sanitizer caches built-in options, compiled policy lookups, and DOM parsers.
Reusable sanitizers also reuse compiled policy sets.

The benchmark suite covers documents, reusable policies, denied wrappers, nested
CSS functions, and large URL lists.

Run the benchmark suite in the target environment:

```bash
lpm run bench
```

Measurements depend on the runtime, computer, options, and input data.

## Runtime support

- **Node.js:** 18 or later with an explicit DOM runtime
- **Browsers:** Chrome 90+, Firefox 88+, Safari 14+, and Edge 90+
- **Web Workers:** Supported with an explicit DOM runtime
- **Required DOM APIs:** `DOMParser` and `DocumentFragment`
- **Module formats:** ESM and CommonJS
- **TypeScript:** Declaration files are included

The package does not depend on jsdom at runtime. Applications select and install
their DOM implementation.

## Package entry points

| Import                             | Purpose                  |
| ---------------------------------- | ------------------------ |
| `@lpm.dev/neo.sanitize`            | Main API and types       |
| `@lpm.dev/neo.sanitize/core`       | Core sanitizer functions |
| `@lpm.dev/neo.sanitize/validators` | Policy validators        |
| `@lpm.dev/neo.sanitize/schemas`    | Predefined policies      |

## Development

Run the release checks:

```bash
lpm run release:check
```

The test suites cover policy behavior, resource limits, hooks, runtimes, attack
corpora, fuzz cases, and browser engines.

## License

MIT. See [LICENSE](./LICENSE).
