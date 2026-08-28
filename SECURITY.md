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

The sanitizer captures the DOM and parser operations when it first uses a runtime. Do not use a realm that an attacker can modify before this first call.

For Trusted Types, create a dedicated identity policy. Pass this policy only to `sanitizeToTrustedHTML()`.

Do not use the identity policy directly with a DOM sink. Direct use bypasses the sanitizer.

Trusted Types do not replace sanitization. They control which code can send values to protected browser sinks.

For an explicit browser runtime, create the policy in that runtime's realm. The sanitizer validates the result with that realm's Trusted Types factory.

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
- Trusted Types parsing uses policy-created values for all protected parser sinks.
- The Trusted Types policy cannot change its input or return a non-TrustedHTML value.

These checks run against a version-pinned public attack corpus. The suite also mutates that corpus with malformed table, select, SVG, MathML, template, raw-text, and custom-element transitions in every supported insertion context.

The deterministic corpus runs in Chromium, Firefox, WebKit, jsdom, and happy-dom. Pull requests run exact structural comparisons for parser-compatible cases and per-runtime security invariants for malformed corpus mutations across these implementations.

A scheduled workflow runs longer mutation campaigns. Fast-check reports a seed and path when it finds a failure.

Add each minimized failure to a deterministic regression test. Do not rely only on the saved fast-check seed.

The external corpus metadata includes the DOMPurify version, release commit, source SHA-256, and case count.

The weekly update workflow opens a pull request when DOMPurify publishes a new release. The workflow also starts the full CI matrix.

A maintainer must review upstream changes before merge.

Use this command to compare the repository with the latest DOMPurify release:

```bash
lpm run corpus:update
```

Set `DOMPURIFY_VERSION` to import a specific release tag.

Use this command to import a fixture from a reviewed local checkout:

```bash
node scripts/import-dompurify-corpus.mjs /path/to/expect.mjs 3.4.14 <commit> <sha256>
```

The import parser does not execute the upstream fixture module.

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

## Vulnerability Response

The private GitHub advisory is the record for each vulnerability report.

The response targets are:

- Acknowledge the report within three business days.
- Complete the first severity assessment within seven business days.
- Give the reporter a status update at least every seven days.
- Publish the correction as soon as coordinated disclosure permits.

These targets are service targets. Complex browser behavior can require more investigation.

### Response Procedure

1. Create or update the private advisory.
2. Reproduce the report on a supported version.
3. Record the affected sinks, runtimes, options, and browser engines.
4. Assign a severity with CVSS and document the attack requirements.
5. Develop the correction in the advisory private fork.
6. Add a minimized regression case before release.
7. Run the release, corpus, fuzz, browser, package, and performance checks.
8. Request review from a maintainer who did not write the correction.
9. Prepare the package version, changelog, advisory, and release notes together.
10. Publish the package and advisory on the coordinated disclosure date.
11. Credit the reporter unless the reporter requests anonymity.
12. Monitor new reports and downstream feedback after release.

Do not put embargoed details in public branches, pull requests, issues, logs, or CI artifacts.

If a fuzz job fails, download its retained artifact. The artifact contains the sanitizer version, source commit, corpus pin, run counts, and failure log.

The workflow retains each failure artifact for 30 days.

## Report a Vulnerability

Do not report a vulnerability in a public issue.

Use the [private vulnerability report](https://github.com/ne-ooo/neo.sanitize/security/advisories/new) for this repository.

Include the affected version, a reproduction case, and the security impact.

If a proposed correction is available, include it.

Do not include secrets or personal data in the report.
