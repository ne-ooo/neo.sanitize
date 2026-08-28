# Security Policy

## Threat Model

neo.sanitize accepts an attacker-controlled HTML string. The sanitizer returns an HTML string or a `DocumentFragment`.

The sanitizer supports HTML output only. It removes SVG, MathML, and all other foreign namespaces.

The default policy removes these content types:

- Active elements, such as `script`, `iframe`, `object`, `style`, and `template`.
- Event-handler attributes.
- Unsafe URL protocols.
- Inline CSS, unless the application enables it.
- Custom elements and customized built-ins.

An application can enable custom elements with `allowCustomElements`. This option is unsafe for attacker-controlled input.

WARNING: Custom-element insertion can run application code. Use this option only with trusted input and trusted custom-element definitions.

The sanitizer ignores inherited configuration properties. It also ignores configuration accessors.

### Application Requirements

Use the output only in an HTML element-content context. Do not use it in JavaScript, CSS, URL, or attribute contexts.

Set `insertionContext` to the element that will receive the output. This is required for table and select content.

The sanitizer rejects raw-text, script, style, template, and foreign-namespace insertion contexts.

Treat hooks as trusted application code. A hook cannot retain a blocked element, but the hook itself can run arbitrary code.

Use a trusted DOM runtime. The `document` and `DOMParser` values must come from the same implementation.

Do not use a realm that an attacker can modify with JavaScript. An attacker with this access can replace DOM prototypes before sanitization.

Do not add unsafe markup after sanitization. A later string transformation or DOM mutation can invalidate the result.

Use application isolation for attacker-controlled layout. Strict CSS validation does not prevent interface redressing.

### Security Invariants

The test suite checks these invariants:

- Active elements do not remain in the output.
- Event-handler attributes do not remain in the output.
- Unsafe URL protocols do not remain in URL attributes.
- Unsupported namespaces do not remain in the output.
- A repeated parse and sanitize operation does not create active content.
- Parser errors and resource-limit failures return empty output.
- Inherited configuration cannot make the policy less restrictive.
- Structured contextual cases have the same element, namespace, ancestry, and attribute signature across supported DOM implementations.
- Malformed contextual mutations satisfy the same security invariants in every implementation, even when standards-permitted parser recovery produces different benign trees or text.

These checks run against a version-pinned public attack corpus. The suite also mutates that corpus with malformed table, select, SVG, MathML, template, raw-text, and custom-element transitions in every supported insertion context.

The deterministic corpus runs in Chromium, Firefox, WebKit, jsdom, and happy-dom. Pull requests run exact structural comparisons for parser-compatible cases and per-runtime security invariants for malformed corpus mutations across these implementations.

A scheduled workflow runs longer mutation campaigns. Fast-check reports a seed and path when it finds a failure.

Add each minimized failure to a deterministic regression test. Do not rely only on the saved fast-check seed.

The current external corpus comes from DOMPurify 3.4.14. See `test/corpus/THIRD_PARTY_NOTICES.md` for its source and license.

Use this command to update the imported corpus from a reviewed DOMPurify checkout:

```bash
node scripts/import-dompurify-corpus.mjs /path/to/DOMPurify/test/fixtures/expect.mjs
```

Update the pinned version, commit, notice, and fixture count in the same change.

### Resource Limits

The sanitizer checks the input length before DOM parsing. It also uses HTML-depth, DOM-depth, and DOM-node limits.

The sanitizer returns empty output when an input exceeds a limit. Applications must also set request limits outside this package.

Resource limits reduce work inside the sanitizer. They do not replace process isolation for hostile multi-tenant workloads.

### Out of Scope

The package does not preserve SVG, MathML, declarative shadow DOM, embedded documents, or active form controls.

The package does not make attacker-controlled CSS safe for page layout. The package does not apply Content Security Policy.

The package does not protect a JavaScript realm that an attacker already controls. The package does not sanitize later application mutations.

## Supported Versions

| Version | Security updates |
| --- | --- |
| 1.x | Yes |
| Earlier versions | No |

## Report a Vulnerability

Do not report a vulnerability in a public issue.

Use the [private vulnerability report](https://github.com/ne-ooo/neo.sanitize/security/advisories/new) for this repository.

Include the affected version, a reproduction case, and the security impact.

If a proposed correction is available, include it.

Do not include secrets or personal data in the report.
