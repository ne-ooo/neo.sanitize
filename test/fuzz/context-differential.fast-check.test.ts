// @vitest-environment node

import { Window } from 'happy-dom'
import { JSDOM } from 'jsdom'
import { describe, expect, it } from 'vitest'
import * as fc from 'fast-check'
import { sanitize, serializeHTML } from '../../src/index.js'
import type { DOMRuntime } from '../../src/types.js'
import {
  adversarialContextHTMLCaseArbitrary,
  differentialHTMLCaseArbitrary,
} from '../differential/arbitraries.js'
import { getHTMLSecurityStructure } from '../differential/security-structure.js'
import { assertHTMLSecurityInvariants } from '../security/security-invariants.js'

const fuzzRuns = Number(process.env.DIFFERENTIAL_FUZZ_RUNS ?? 300)
const adversarialFuzzRuns = Number(
  process.env.ADVERSARIAL_CONTEXT_FUZZ_RUNS ?? Math.min(fuzzRuns, 1_000)
)
const fuzzSeed = Number(process.env.DIFFERENTIAL_FUZZ_SEED ?? 0x434f4e54)
const fuzzTimeout = Math.max(
  10_000,
  Math.max(fuzzRuns, adversarialFuzzRuns) * 8
)

const jsdomWindow = new JSDOM('').window
const happyWindow = new Window()
const jsdomRuntime: DOMRuntime = {
  document: jsdomWindow.document,
  DOMParser: jsdomWindow.DOMParser,
}
const happyDOMRuntime: DOMRuntime = {
  document: happyWindow.document as unknown as Document,
  DOMParser: happyWindow.DOMParser as unknown as typeof DOMParser,
}

describe('context-aware DOM runtime differential fuzzing', () => {
  it('produces equivalent secure output in jsdom and happy-dom', () => {
    fc.assert(
      fc.property(differentialHTMLCaseArbitrary, ({ context, payload }) => {
        const options = { insertionContext: context }
        const jsdomClean = sanitize(payload, options, jsdomRuntime) as string
        const happyClean = sanitize(payload, options, happyDOMRuntime) as string
        const stableOptions = { ...options, detectMXSS: true }
        const jsdomStable = sanitize(
          payload,
          stableOptions,
          jsdomRuntime
        ) as string
        const happyStable = sanitize(
          payload,
          stableOptions,
          happyDOMRuntime
        ) as string

        expect(
          getHTMLSecurityStructure(happyClean, happyDOMRuntime, context)
        ).toBe(getHTMLSecurityStructure(jsdomClean, jsdomRuntime, context))
        expect(
          getHTMLSecurityStructure(happyStable, happyDOMRuntime, context)
        ).toBe(getHTMLSecurityStructure(jsdomStable, jsdomRuntime, context))
        assertHTMLSecurityInvariants(jsdomClean, jsdomRuntime, context)
        assertHTMLSecurityInvariants(happyClean, happyDOMRuntime, context)
        assertHTMLSecurityInvariants(jsdomStable, jsdomRuntime, context)
        assertHTMLSecurityInvariants(happyStable, happyDOMRuntime, context)
        expect(sanitize(jsdomStable, stableOptions, jsdomRuntime)).toBe(
          jsdomStable
        )
        expect(sanitize(happyStable, stableOptions, happyDOMRuntime)).toBe(
          happyStable
        )
      }),
      { numRuns: fuzzRuns, seed: fuzzSeed, verbose: true }
    )
  }, fuzzTimeout)

  it('produces equivalent contextual fragments', () => {
    fc.assert(
      fc.property(differentialHTMLCaseArbitrary, ({ context, payload }) => {
        const options = {
          insertionContext: context,
          returnString: false as const,
          detectMXSS: true,
        }
        const jsdomFragment = sanitize(
          payload,
          options,
          jsdomRuntime
        ) as DocumentFragment
        const happyFragment = sanitize(
          payload,
          options,
          happyDOMRuntime
        ) as DocumentFragment

        const jsdomHTML = serializeHTML(jsdomFragment)
        const happyHTML = serializeHTML(happyFragment)
        expect(
          getHTMLSecurityStructure(happyHTML, happyDOMRuntime, context)
        ).toBe(getHTMLSecurityStructure(jsdomHTML, jsdomRuntime, context))
      }),
      { numRuns: Math.min(fuzzRuns, 500), seed: fuzzSeed ^ 0x46524147 }
    )
  }, fuzzTimeout)

  it('keeps corpus-seeded malformed contexts secure in both runtimes', () => {
    fc.assert(
      fc.property(
        adversarialContextHTMLCaseArbitrary,
        ({ context, payload }) => {
          const options = { insertionContext: context }
          const stableOptions = { ...options, detectMXSS: true }

          for (const runtime of [jsdomRuntime, happyDOMRuntime]) {
            const clean = sanitize(payload, options, runtime) as string
            const stable = sanitize(payload, stableOptions, runtime) as string

            assertHTMLSecurityInvariants(clean, runtime, context)
            assertHTMLSecurityInvariants(stable, runtime, context)
            expect(sanitize(stable, stableOptions, runtime)).toBe(stable)
          }
        }
      ),
      {
        numRuns: adversarialFuzzRuns,
        seed: fuzzSeed ^ 0x41445652,
        verbose: true,
      }
    )
  }, fuzzTimeout)
})
