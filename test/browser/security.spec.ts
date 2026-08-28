import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { expect, test } from '@playwright/test'
import * as fc from 'fast-check'

interface Corpus {
  cases: Array<{ id: string; title: string; payload: string }>
}

const browserFuzzRuns = Number(process.env.BROWSER_FUZZ_RUNS ?? 40)
const attackTokens = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg><foreignObject><p onclick=alert(1)>x</p></foreignObject></svg>',
  '<math><mtext><mglyph><style><!--</style><img src onerror=alert(1)>',
  '<template shadowrootmode=open><a href=javascript:alert(1)>x</a></template>',
  '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
  '<user-card onclick=alert(1)>x</user-card>',
  '<p is=dangerous-paragraph>text</p>',
  '<a href="java\tscript:alert(1)">x</a>',
  '<!--',
  '-->',
  '</style>',
  '</textarea>',
  '</noscript>',
]

const browserRegressions = [
  {
    id: 'form-next-sibling-clobber',
    title: 'form named property must not skip active siblings',
    payload:
      '<form><input name="nextSibling"></form>' +
      '<img src=x onerror="window.__xss=1">' +
      '<script>window.__xss=2</script>',
  },
  {
    id: 'inert-parser-adoption',
    title: 'parsing must not execute a handler before sanitization',
    payload: '</textarea><img src=x onerror=alert(1)>',
  },
]

const generatedPayloads = fc.sample(
  fc
    .array(
      fc.oneof(
        fc.constantFrom(...attackTokens),
        fc.string({ maxLength: 80 })
      ),
      { minLength: 1, maxLength: 12 }
    )
    .map((parts) => parts.join('')),
  { seed: 0x4e454f, numRuns: browserFuzzRuns }
)

test('public corpus and generated markup satisfy browser security invariants', async ({
  page,
  browserName,
}) => {
  const dialogs: string[] = []
  page.on('dialog', async (dialog) => {
    dialogs.push(dialog.message())
    await dialog.dismiss()
  })

  const moduleSource = await readFile(resolve('dist/index.js'), 'utf8')
  const corpus = JSON.parse(
    await readFile(resolve('test/corpus/dompurify-v3.4.14.json'), 'utf8')
  ) as Corpus
  const cases = [
    ...browserRegressions,
    ...corpus.cases.map(({ id, title, payload }) => ({ id, title, payload })),
    ...generatedPayloads.map((payload, index) => ({
      id: `generated-${index + 1}`,
      title: 'deterministic browser fuzz input',
      payload,
    })),
  ]

  const failure = await page.evaluate(
    async ({ source, inputs, engine }) => {
      const moduleURL = URL.createObjectURL(
        new Blob([source], { type: 'text/javascript' })
      )

      try {
        const sanitizer = await import(moduleURL)
        const parserContextAttributes = new Set([
          'is',
          'shadowrootclonable',
          'shadowrootdelegatesfocus',
          'shadowrootmode',
          'shadowrootserializable',
          'srcdoc',
        ])
        const urlAttributes = new Set(sanitizer.URL_ATTRIBUTES)

        const inspect = (html: string): void => {
          const template = document.createElement('template')
          template.innerHTML = html

          for (const element of Array.from(template.content.querySelectorAll('*'))) {
            const tagName = element.localName.toLowerCase()
            if (element.namespaceURI !== 'http://www.w3.org/1999/xhtml') {
              throw new Error(`foreign namespace survived on <${tagName}>`)
            }
            if (sanitizer.isDangerousTag(tagName)) {
              throw new Error(`active element survived: <${tagName}>`)
            }
            if (tagName.includes('-')) {
              throw new Error(`custom element survived: <${tagName}>`)
            }

            for (const attribute of Array.from(element.attributes)) {
              const name = attribute.name.toLowerCase()
              if (name.startsWith('on')) {
                throw new Error(`event handler survived: ${name}`)
              }
              if (name === 'style') {
                throw new Error('inline style survived the default policy')
              }
              if (parserContextAttributes.has(name)) {
                throw new Error(`parser-context attribute survived: ${name}`)
              }
              if (
                urlAttributes.has(name) &&
                !sanitizer.isSafeURLAttributeValue(name, attribute.value)
              ) {
                throw new Error(`unsafe URL survived in ${name}`)
              }
            }
          }
        }

        for (const input of inputs) {
          try {
            const clean = sanitizer.sanitize(input.payload)
            const sanitizedReparse = sanitizer.sanitize(clean)
            const stable = sanitizer.sanitize(input.payload, { detectMXSS: true })

            inspect(clean)
            inspect(sanitizedReparse)
            inspect(stable)

            if (sanitizer.sanitize(stable, { detectMXSS: true }) !== stable) {
              throw new Error('mXSS output was not stable')
            }
          } catch (error) {
            return `${engine} ${input.id} ${input.title}: ${String(error)}`
          }
        }

        const clobbering = inputs.find(
          (input) => input.id === 'form-next-sibling-clobber'
        )
        if (!clobbering) throw new Error('clobbering regression is missing')

        const fragment = sanitizer.sanitize(clobbering.payload, {
          returnString: false,
        })
        const fragmentHTML = sanitizer.serializeHTML(fragment)
        inspect(fragmentHTML)
        if (fragmentHTML !== '<img src="x">') {
          throw new Error(`unexpected fragment output: ${fragmentHTML}`)
        }

        return null
      } finally {
        URL.revokeObjectURL(moduleURL)
      }
    },
    { source: moduleSource, inputs: cases, engine: browserName }
  )

  expect(failure).toBeNull()
  expect(dialogs, `${browserName} executed a dialog while sanitizing`).toEqual([])
})
