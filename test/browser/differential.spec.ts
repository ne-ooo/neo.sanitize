import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { expect, test } from '@playwright/test'
import { JSDOM } from 'jsdom'
import * as fc from 'fast-check'
import { sanitize } from '../../src/index.js'
import type { DOMRuntime } from '../../src/types.js'
import {
  adversarialContextHTMLCaseArbitrary,
  differentialHTMLCaseArbitrary,
} from '../differential/arbitraries.js'
import { getHTMLSecurityStructure } from '../differential/security-structure.js'

const browserFuzzRuns = Number(process.env.BROWSER_DIFFERENTIAL_RUNS ?? 40)
const browserFuzzSeed = Number(
  process.env.BROWSER_DIFFERENTIAL_SEED ?? 0x42524f57
)
const jsdomWindow = new JSDOM('').window
const jsdomRuntime: DOMRuntime = {
  document: jsdomWindow.document,
  DOMParser: jsdomWindow.DOMParser,
}

test('contextual output matches the jsdom security structure', async ({
  page,
  browserName,
}) => {
  const dialogs: string[] = []
  page.on('dialog', async (dialog) => {
    dialogs.push(dialog.message())
    await dialog.dismiss()
  })

  const moduleSource = await readFile(resolve('dist/index.js'), 'utf8')
  await page.evaluate(async (source) => {
    const moduleURL = URL.createObjectURL(
      new Blob([source], { type: 'text/javascript' })
    )
    const sanitizer = await import(moduleURL)
    Object.assign(globalThis, {
      __neoSanitizer: sanitizer,
      __neoSanitizerModuleURL: moduleURL,
    })
  }, moduleSource)

  try {
    await fc.assert(
      fc.asyncProperty(
        differentialHTMLCaseArbitrary,
        async ({ context, payload }) => {
          const options = { insertionContext: context }
          const stableOptions = { ...options, detectMXSS: true }
          const referenceClean = sanitize(
            payload,
            options,
            jsdomRuntime
          ) as string
          const referenceStable = sanitize(
            payload,
            stableOptions,
            jsdomRuntime
          ) as string
          const referenceCleanStructure = getHTMLSecurityStructure(
            referenceClean,
            jsdomRuntime,
            context
          )
          const referenceStableStructure = getHTMLSecurityStructure(
            referenceStable,
            jsdomRuntime,
            context
          )

          const browserResult = await page.evaluate(
            ({ insertionContext, dirty }) => {
              const state = globalThis as typeof globalThis & {
                __neoSanitizer: {
                  sanitize(
                    html: string,
                    options: Record<string, unknown>
                  ): string
                }
              }
              const sanitizer = state.__neoSanitizer
              const clean = sanitizer.sanitize(dirty, {
                insertionContext,
              })
              const stable = sanitizer.sanitize(dirty, {
                insertionContext,
                detectMXSS: true,
              })

              const structure = (html: string): string => {
                const container = document.createElement(insertionContext)
                container.innerHTML = html
                const elements = Array.from(container.querySelectorAll('*'))
                const elementIndexes = new Map(
                  elements.map((element, index) => [element, index])
                )

                return JSON.stringify(
                  elements.map((element) => ({
                    tag: element.localName.toLowerCase(),
                    namespace: element.namespaceURI,
                    parentIndex:
                      element.parentElement === container
                        ? null
                        : element.parentElement
                          ? (elementIndexes.get(element.parentElement) ?? null)
                          : null,
                    attributes: Array.from(element.attributes)
                      .map(({ name, value }) => [name.toLowerCase(), value])
                      .sort(([left], [right]) =>
                        String(left).localeCompare(String(right))
                      ),
                  }))
                )
              }

              return {
                cleanStructure: structure(clean),
                stableStructure: structure(stable),
                stableAgain:
                  sanitizer.sanitize(stable, {
                    insertionContext,
                    detectMXSS: true,
                  }) === stable,
              }
            },
            { insertionContext: context, dirty: payload }
          )

          expect(browserResult.cleanStructure).toBe(referenceCleanStructure)
          expect(browserResult.stableStructure).toBe(referenceStableStructure)
          expect(browserResult.stableAgain).toBe(true)
        }
      ),
      {
        numRuns: browserFuzzRuns,
        seed: browserFuzzSeed,
        verbose: true,
      }
    )

    await fc.assert(
      fc.asyncProperty(
        adversarialContextHTMLCaseArbitrary,
        async ({ context, payload }) => {
          const browserResult = await page.evaluate(
            ({ insertionContext, dirty }) => {
              const state = globalThis as typeof globalThis & {
                __neoSanitizer: {
                  URL_ATTRIBUTES: readonly string[]
                  isDangerousTag(tagName: string): boolean
                  isSafeURLAttributeValue(name: string, value: string): boolean
                  sanitize(
                    html: string,
                    options: Record<string, unknown>
                  ): string
                }
              }
              const sanitizer = state.__neoSanitizer
              const options = { insertionContext }
              const stableOptions = { insertionContext, detectMXSS: true }
              const clean = sanitizer.sanitize(dirty, options)
              const stable = sanitizer.sanitize(dirty, stableOptions)
              const parserContextAttributes = new Set([
                'is',
                'shadowrootclonable',
                'shadowrootdelegatesfocus',
                'shadowrootmode',
                'shadowrootserializable',
                'srcdoc',
              ])
              const urlAttributes = new Set(sanitizer.URL_ATTRIBUTES)

              const inspect = (html: string): string | null => {
                const container = document.createElement(insertionContext)
                container.innerHTML = html

                for (const element of Array.from(
                  container.querySelectorAll('*')
                )) {
                  const tagName = element.localName.toLowerCase()
                  if (
                    element.namespaceURI !==
                    'http://www.w3.org/1999/xhtml'
                  ) {
                    return `foreign namespace survived on <${tagName}>`
                  }
                  if (sanitizer.isDangerousTag(tagName)) {
                    return `active element survived: <${tagName}>`
                  }
                  if (tagName.includes('-')) {
                    return `custom element survived: <${tagName}>`
                  }

                  for (const attribute of Array.from(element.attributes)) {
                    const name = attribute.name.toLowerCase()
                    if (name.startsWith('on')) {
                      return `event handler survived: ${name}`
                    }
                    if (name === 'style') {
                      return 'inline style survived the default policy'
                    }
                    if (parserContextAttributes.has(name)) {
                      return `parser-context attribute survived: ${name}`
                    }
                    if (
                      urlAttributes.has(name) &&
                      !sanitizer.isSafeURLAttributeValue(name, attribute.value)
                    ) {
                      return `unsafe URL survived in ${name}`
                    }
                  }
                }

                return null
              }

              return {
                cleanViolation: inspect(clean),
                stableViolation: inspect(stable),
                stableAgain:
                  sanitizer.sanitize(stable, stableOptions) === stable,
              }
            },
            { insertionContext: context, dirty: payload }
          )

          expect(browserResult.cleanViolation).toBeNull()
          expect(browserResult.stableViolation).toBeNull()
          expect(browserResult.stableAgain).toBe(true)
        }
      ),
      {
        numRuns: browserFuzzRuns,
        seed: browserFuzzSeed ^ 0x41445652,
        verbose: true,
      }
    )
  } finally {
    await page.evaluate(() => {
      const state = globalThis as typeof globalThis & {
        __neoSanitizerModuleURL?: string
      }
      if (state.__neoSanitizerModuleURL) {
        URL.revokeObjectURL(state.__neoSanitizerModuleURL)
      }
    })
  }

  expect(dialogs, `${browserName} executed a dialog while sanitizing`).toEqual([])
})
