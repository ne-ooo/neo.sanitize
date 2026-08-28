# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- Added a version-pinned public attack corpus with Apache-2.0 attribution.
- Added browser-engine, DOM-runtime, parser-context, and property-fuzz checks.
- Added context-aware parsing for ordinary, table, and select insertion targets.
- Added shrinkable structural differential fuzzing and corpus-seeded malformed context mutations across five DOM implementations.
- Added `sanitizeToTrustedHTML()` for browser applications that enforce Trusted Types.
- Added test coverage gates for statements, branches, functions, and lines.
- Added package checks for public exports, skill versions, required files, and the bundle budget.
- Added CI checks for Node.js 18, 20, and 22.
- Added the MIT license and a private vulnerability reporting policy.

### Security

- Custom elements and customized built-ins now require an explicit unsafe opt-in.
- Inherited and accessor-backed configuration properties can no longer broaden policy.
- Raw browser nodes remain in the inert parser document until sanitization finishes.
- DOM named properties can no longer skip traversal or shadow sanitizer operations.
- Added a published threat model and security invariants.
- Foreign namespaces are now removed for all policies. Custom tag lists cannot retain active SVG or MathML content.
- DOM-clobbering prevention now removes all `id` and `name` attributes. It no longer relies on a finite list of names.
- Deep DOM input now fails closed at the sanitizer depth limit instead of exhausting the JavaScript call stack.
- Input length, raw markup depth, DOM node count, and DOM depth now have fail-closed limits before and after parsing.
- The raw depth preflight now follows bounded HTML tokenizer states and charges implicit table levels.
- Ambiguous raw text and CDATA in unsupported foreign content now fail closed before parsing.
- DOM runtime parser failures now fail closed in the sanitizer and use a normalized error in the public parser API.
- Public attribute validators no longer read inherited record properties for attacker-controlled tag names.
- Unknown schema names now throw instead of falling back to a richer default policy.
- The package allowlist now includes `.lpm/skills` only. Generated LPM state is not included.
- Active-content tags now stay blocked when a custom `allowedTags` list contains them.
- The relaxed schema no longer permits arbitrary attributes on `code` and `pre`.
- URL-list attributes now check the protocol of each URL candidate.
- CSS validation now parses declarations, comments, escapes, and functions.
- Strict CSS validation now removes URL and dynamic functions.
- Node.js and Web Workers can supply an explicit DOM runtime.
- Removed safe wrappers now retain sanitized child markup.
- The `stripTags` option now removes allowed wrappers too.
- A hook-free pass now checks all hook mutations.
- Shared policies are deeply frozen. `getConfig()` returns frozen copies.
- Foreign namespaces stay blocked during experimental mXSS stabilization.
- The experimental mXSS mode now requires stable output after reparsing.

### Performance

- Core and mXSS tree traversal now use explicit stacks instead of JavaScript recursion.
- Denied wrappers are rebuilt into a linear output tree instead of repeatedly moving retained descendants through every ancestor.
- Hook-free sanitization now rebuilds only the denied subtree. Allowed siblings remain in place.
- mXSS string output now reuses the serialization from the stable pass.
- URL-list validation now streams candidates and stops at the first unsafe URL.
- CSS function validation now uses a single iterative tokenizer instead of rescanning nested argument substrings.
- Style validation now performs the global CSS scan once.
- Reusable sanitizers now cache resolved configuration and compiled policy lookups.
- Added `compileSanitizeOptions()` for hook-free direct calls that reuse options with different runtimes.
- DOM parser instances are now reused for each runtime.
- Hook-free traversal now avoids temporary child and attribute arrays.
- Hook-free trees without wrapper promotion use an in-place string fast path.
- Scalar URL validation now avoids temporary candidate arrays and result objects.
- Benchmarks now cover scaling, compiled policies, hostile wrappers, nested CSS functions, and large URL lists.
- CI now checks output parity, scaling ratios, allocation ratios, nested CSS, and URL-list short-circuiting.
- DOM traversal now captures validated node, attribute, and parser operations once for each runtime.
- A one-time sibling probe removes repeated compatibility checks from compliant runtimes.

### Changed

- The release check now uses LPM for type checks, coverage, builds, and package checks.
- The package now includes an LPM lockfile for reproducible CI installs.
- The development toolchain now uses patched Vitest, Vite, and esbuild versions.
- Documentation now reports the measured bundle size and current test count.
- Inline-style guidance now distinguishes XSS/resource filtering from layout isolation.
- Builds are minified without published source maps, and release checks enforce raw entry and total distribution budgets.

## [1.0.0] - 2026-03-19

### Added

- **`sanitize(html, options?)`** — Sanitize HTML strings with a fail-closed HTML policy
- **`createSanitizer(options)`** — Create a reusable sanitizer with fixed configuration
- **`BASIC` schema** — Common safe tags: p, br, strong, em, a, ul, ol, li, etc.
- **`RELAXED` schema** — Extended tags including tables, code blocks, images
- **`STRICT` schema** — Text-only, strips all HTML
- **`./core`** sub-path export — Low-level sanitizer primitives
- **`./validators`** sub-path export — Attribute and URL validators
- **`./schemas`** sub-path export — Built-in schema configurations
- Uses native browser DOMParser — no eval, no RegEx-based sanitization
- Cross-realm safe — works in iframes and workers
- Node.js support via `jsdom` (optional)
- Zero runtime dependencies
- ESM + CJS dual output with TypeScript declaration files
- Tree-shakeable (`sideEffects: false`)
