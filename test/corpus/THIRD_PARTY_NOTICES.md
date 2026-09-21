# Third-Party Test Corpus

`dompurify-v3.4.15.json` contains modified test fixtures from DOMPurify.

- Project: DOMPurify
- Source: `test/fixtures/expect.mjs`
- Version: 3.4.15
- Commit: `1d7460c4f8a27be825c11b1c9d346d79db32c1e5`
- Source SHA-256: `1c8f8dad1874fcd375665070a8e2be8e011b63a6d6b2ce27ab08585e324eef75`
- Copyright: Cure53 and other contributors
- License: Apache License 2.0
- Repository: <https://github.com/cure53/DOMPurify>

neo.sanitize retained each payload and each available title. It added stable labels for untitled fixtures.

neo.sanitize removed the DOMPurify-specific expected output.

neo.sanitize checks its own HTML-only security invariants. DOMPurify and Cure53 do not endorse these modifications.

The full Apache License 2.0 is in `LICENSE-DOMPURIFY.txt`.
