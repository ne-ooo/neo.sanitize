# Third-Party Test Corpus

`dompurify-v3.4.17.json` contains modified test fixtures from DOMPurify.

- Project: DOMPurify
- Source: `test/fixtures/expect.mjs`
- Version: 3.4.17
- Commit: `a77a3e78b59f72fa4d1c83f22e121ad9cc7d3575`
- Source SHA-256: `1c8f8dad1874fcd375665070a8e2be8e011b63a6d6b2ce27ab08585e324eef75`
- Copyright: Cure53 and other contributors
- License: Apache License 2.0
- Repository: <https://github.com/cure53/DOMPurify>

neo.sanitize retained each payload and each available title. It added stable labels for untitled fixtures.

neo.sanitize removed the DOMPurify-specific expected output.

neo.sanitize checks its own HTML-only security invariants. DOMPurify and Cure53 do not endorse these modifications.

The full Apache License 2.0 is in `LICENSE-DOMPURIFY.txt`.
