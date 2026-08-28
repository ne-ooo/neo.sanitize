import { describe, expect, it } from 'vitest'
import * as fc from 'fast-check'
import { sanitize } from '../../src/index.js'
import type { SanitizeOptions } from '../../src/types.js'
import corpus from '../corpus/dompurify-v3.4.14.json'
import { assertHTMLSecurityInvariants } from '../security/security-invariants.js'

const fuzzRuns = Number(process.env.FUZZ_RUNS ?? 300)
const fuzzSeed = Number(process.env.FUZZ_SEED ?? 0x4e454f)
const fuzzTimeout = Math.max(5_000, fuzzRuns * 3)
const seedPayloads = corpus.cases.map(({ payload }) => payload)
const syntaxTokens = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg><p onclick=alert(1)>x</p></svg>',
  '<math><mtext><mglyph><style><!--</style><img src onerror=alert(1)>',
  '<template shadowrootmode=open><a href=javascript:alert(1)>x</a></template>',
  '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
  '<user-card onclick=alert(1)>x</user-card>',
  '<p is=dangerous-paragraph>text</p>',
  '<a href="javascript:alert(1)">x</a>',
  '<a href="java\tscript:alert(1)">x</a>',
  '<!--',
  '-->',
  '<![CDATA[',
  '</style>',
  '</textarea>',
  '</noscript>',
  '&Tab;',
  '&#x00;',
]

const generatedMarkup = fc
  .array(
    fc.oneof(fc.constantFrom(...syntaxTokens), fc.string({ maxLength: 100 })),
    { minLength: 1, maxLength: 16 }
  )
  .map((parts) => parts.join(''))

const mutatedCorpusPayload = fc
  .tuple(
    fc.constantFrom(...seedPayloads),
    fc.string({ maxLength: 60 }),
    fc.string({ maxLength: 60 }),
    fc.array(fc.constantFrom(...syntaxTokens), { maxLength: 4 })
  )
  .map(([payload, prefix, suffix, mutations]) =>
    [prefix, ...mutations, payload, suffix].join('')
  )

const hostilePrototype = fc.record({
  allowedTags: fc.constant(['script', 'iframe', 'user-card']),
  allowedAttributes: fc.constant({ script: ['src'], 'user-card': ['onclick'] }),
  allowAllAttributes: fc.constant(['script', 'iframe', 'user-card']),
  allowCustomElements: fc.constant(true),
  allowStyleAttribute: fc.constant(true),
  insertionContext: fc.constant('script'),
  detectMXSS: fc.boolean(),
})

describe('mutation-guided sanitizer fuzzing', () => {
  it('keeps default and mXSS output inside the HTML security invariants', () => {
    fc.assert(
      fc.property(
        fc.oneof(generatedMarkup, mutatedCorpusPayload),
        (dirty) => {
          const clean = sanitize(dirty) as string
          const sanitizedReparse = sanitize(clean) as string
          const stable = sanitize(dirty, { detectMXSS: true }) as string

          assertHTMLSecurityInvariants(clean)
          assertHTMLSecurityInvariants(sanitizedReparse)
          assertHTMLSecurityInvariants(stable)
          expect(sanitize(stable, { detectMXSS: true })).toBe(stable)
        }
      ),
      { numRuns: fuzzRuns, seed: fuzzSeed }
    )
  }, fuzzTimeout)

  it('ignores configuration inherited from hostile prototypes', () => {
    fc.assert(
      fc.property(generatedMarkup, hostilePrototype, (dirty, prototype) => {
        const options = Object.create(prototype) as Partial<SanitizeOptions>
        const clean = sanitize(dirty, options) as string

        assertHTMLSecurityInvariants(clean)
      }),
      { numRuns: fuzzRuns, seed: fuzzSeed ^ 0x50524f54 }
    )
  }, fuzzTimeout)

  it('does not invoke accessor-backed configuration properties', () => {
    fc.assert(
      fc.property(
        generatedMarkup,
        fc.constantFrom<keyof SanitizeOptions>(
          'allowedTags',
          'allowedAttributes',
          'allowAllAttributes',
          'allowCustomElements',
          'allowStyleAttribute',
          'insertionContext',
          'hooks'
        ),
        (dirty, key) => {
          let accessed = false
          const options: Partial<SanitizeOptions> = {}
          Object.defineProperty(options, key, {
            enumerable: true,
            get: () => {
              accessed = true
              throw new Error('configuration accessor ran')
            },
          })

          const clean = sanitize(dirty, options) as string
          expect(accessed).toBe(false)
          assertHTMLSecurityInvariants(clean)
        }
      ),
      { numRuns: fuzzRuns, seed: fuzzSeed ^ 0x41434345 }
    )
  }, fuzzTimeout)
})
