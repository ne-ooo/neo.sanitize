# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- Added test coverage gates for statements, branches, functions, and lines.
- Added package checks for public exports, skill versions, required files, and the bundle budget.
- Added CI checks for Node.js 18, 20, and 22.
- Added the MIT license and a private vulnerability reporting policy.

### Security

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
- The experimental mXSS mode now removes foreign namespaces.
- The experimental mXSS mode now requires stable output after reparsing.

### Performance

- Reusable sanitizers now cache resolved configuration and compiled policy lookups.
- DOM parser instances are now reused for each runtime.
- Hook-free traversal now avoids temporary child and attribute arrays.
- String sanitization now avoids fragment cloning and cross-document adoption.
- Scalar URL validation now avoids temporary candidate arrays and result objects.
- Local paired-build measurements showed approximately 66% to 167% higher throughput across benchmark inputs.

### Changed

- The release check now uses LPM for type checks, coverage, builds, and package checks.
- The package now includes an LPM lockfile for reproducible CI installs.
- The development toolchain now uses patched Vitest, Vite, and esbuild versions.
- Documentation now reports the measured bundle size and current test count.

## [1.0.0] - 2026-03-19

### Added

- **`sanitize(html, options?)`** — Sanitize HTML strings, blocking 143+ XSS vectors
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
