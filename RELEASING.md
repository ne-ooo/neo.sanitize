# Security Release Process

Use this process for a release that contains security corrections or security controls.

## Embargoed Work

1. Create a private GitHub advisory.
2. Use the advisory private fork for the correction.
3. Keep exploit details out of public CI and local shared logs.
4. Agree on a disclosure date with the reporter.

## Release Candidate

1. Select the next version with semantic versioning.
2. Update `package.json` and `SANITIZER_VERSION` to the same version.
3. Update every `.lpm/skills` version to the same version.
4. Move completed changelog entries from `Unreleased` to the dated version.
5. Add a minimized regression case for each corrected vulnerability.
6. Run the release checks:

```bash
lpm run release:check
lpm audit --fail-on vuln
lpm publish --check
FUZZ_RUNS=10000 DIFFERENTIAL_FUZZ_RUNS=10000 ADVERSARIAL_CONTEXT_FUZZ_RUNS=2000 lpm run test:fuzz
BROWSER_FUZZ_RUNS=1000 BROWSER_DIFFERENTIAL_RUNS=1000 lpm run test:browser
```

7. Make sure that the security and performance reviews have no open findings.
8. Review the package contents and generated declarations.
9. Merge the release pull request after all required checks pass.

## Publish

CAUTION: Publish only from the reviewed merge commit. A different commit invalidates the recorded results.

1. Create an annotated `v<version>` tag on the merge commit.
2. Push the tag to the `ne-ooo/neo.sanitize` repository.
3. Publish the package with LPM.
4. Create the GitHub release from the matching changelog section.
5. Publish the GitHub advisory on the disclosure date.
6. Make sure that the registry reports the new version and package hash.
7. Install the published package in a clean project.
8. Run one sanitizer smoke test with the installed package.

## After Publish

1. Monitor the private advisory, public issues, and registry for regressions.
2. Add each new minimized payload to the permanent corpus.
3. Record follow-up work in a new pull request.
