# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - 2026-03-09

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
- < 3 KB gzipped
