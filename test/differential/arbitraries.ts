import { readFileSync } from 'node:fs'
import * as fc from 'fast-check'
import type { HTMLInsertionContext } from '../../src/types.js'
import { HTML_INSERTION_CONTEXTS } from '../../src/utils/context.js'

export interface DifferentialHTMLCase {
  context: HTMLInsertionContext
  payload: string
}

const GENERIC_ATOMS = [
  'plain text',
  '<p>safe <strong>text</strong></p>',
  '<a href="https://safe.test/path">safe link</a>',
  '<a href="javascript:alert(1)">unsafe link</a>',
  '<img src="/safe.png" alt="safe">',
  '<img src=x onerror=alert(1)>',
  '<script>alert(1)</script>',
  '<template shadowrootmode=open><img src=x onerror=alert(1)></template>',
  '<user-card onclick=alert(1)>custom</user-card>',
  '<svg><foreignObject><p onclick=alert(1)>foreign</p></foreignObject></svg>',
] as const

const ROW_ATOMS = [
  '<tr><td>safe</td></tr>',
  '<tr><th>heading</th><td><img src=x onerror=alert(1)></td></tr>',
  '<tr><td><script>alert(1)</script>safe</td></tr>',
] as const

const CELL_ATOMS = [
  '<td>safe</td>',
  '<th>heading</th>',
  '<td><img src=x onerror=alert(1)></td>',
  '<td><script>alert(1)</script>safe</td>',
] as const

const MALFORMED_CONTEXT_TOKENS = [
  '<table><tbody><tr><td>',
  '</td></tr></tbody></table>',
  '<table><caption><select><option>',
  '</option></select></caption></table>',
  '<select><optgroup><option>',
  '</option></optgroup></select>',
  '</select><img src=x onerror=alert(1)>',
  '<svg><foreignObject><table><tr><td>',
  '</td></tr></table></foreignObject></svg>',
  '<math><mtext><table><mglyph><style><!--',
  '</style><img src=x onerror=alert(1)>',
  '<div><frameset onload=alert(1)>',
  '<template shadowrootmode=open><table><tr><td>',
  '<user-card is=x onclick=alert(1)>',
  '<!--',
  '-->',
  '<![CDATA[',
  '</textarea>',
  '</noscript>',
] as const

const corpus = JSON.parse(
  readFileSync(
    new URL('../corpus/dompurify-v3.4.14.json', import.meta.url),
    'utf8'
  )
) as { cases: Array<{ payload: string }> }
const corpusPayloads = corpus.cases.map(({ payload }) => payload)

const CONTEXT_ATOMS: Record<HTMLInsertionContext, readonly string[]> = {
  body: GENERIC_ATOMS,
  div: GENERIC_ATOMS,
  table: [
    '<caption>safe caption</caption>',
    '<colgroup><col span=2></colgroup>',
    '<thead><tr><th>heading</th></tr></thead>',
    '<tbody><tr><td>safe</td></tr></tbody>',
    '<tfoot><tr><td>footer</td></tr></tfoot>',
    '<tbody><tr><td><img src=x onerror=alert(1)></td></tr></tbody>',
    '<script>alert(1)</script>',
  ],
  caption: GENERIC_ATOMS,
  colgroup: [
    '<col span=1>',
    '<col span=2><col span=3>',
    '<script>alert(1)</script>',
    '<template><img src=x onerror=alert(1)></template>',
  ],
  thead: ROW_ATOMS,
  tbody: ROW_ATOMS,
  tfoot: ROW_ATOMS,
  tr: CELL_ATOMS,
  td: GENERIC_ATOMS,
  th: GENERIC_ATOMS,
  select: [
    'plain text',
    '<option>safe option</option>',
    '<optgroup label="safe"><option>nested option</option></optgroup>',
    '<option onclick=alert(1)>unsafe option</option>',
    '<script>alert(1)</script>',
  ],
  optgroup: [
    'plain text',
    '<option>safe option</option>',
    '<option onclick=alert(1)>unsafe option</option>',
    '<img src=x onerror=alert(1)>',
  ],
  option: [
    'plain text',
    '<strong>formatting</strong>',
    '<img src=x onerror=alert(1)>',
    '<script>alert(1)</script>',
  ],
}

export const differentialHTMLCaseArbitrary: fc.Arbitrary<DifferentialHTMLCase> =
  fc.constantFrom(...HTML_INSERTION_CONTEXTS).chain((context) =>
    fc
      .array(fc.constantFrom(...CONTEXT_ATOMS[context]), {
        minLength: 1,
        maxLength: 10,
      })
      .map((parts) => ({ context, payload: parts.join('') }))
  )

export const adversarialContextHTMLCaseArbitrary: fc.Arbitrary<DifferentialHTMLCase> =
  fc.constantFrom(...HTML_INSERTION_CONTEXTS).chain((context) => {
    const contextAtom = fc.constantFrom(...CONTEXT_ATOMS[context])
    const malformedMarkup = fc
      .array(
        fc.oneof(
          contextAtom,
          fc.constantFrom(...MALFORMED_CONTEXT_TOKENS),
          fc.string({ maxLength: 60 })
        ),
        { minLength: 1, maxLength: 12 }
      )
      .map((parts) => parts.join(''))
    const corpusMutation = fc
      .tuple(
        fc.constantFrom(...corpusPayloads),
        fc.string({ maxLength: 40 }),
        fc.string({ maxLength: 40 }),
        fc.array(fc.constantFrom(...MALFORMED_CONTEXT_TOKENS), {
          maxLength: 4,
        })
      )
      .map(([payload, prefix, suffix, mutations]) =>
        [prefix, ...mutations, payload, suffix].join('')
      )

    return fc
      .oneof(
        fc
          .array(contextAtom, { minLength: 1, maxLength: 10 })
          .map((parts) => parts.join('')),
        malformedMarkup,
        corpusMutation
      )
      .map((payload) => ({ context, payload }))
  })
