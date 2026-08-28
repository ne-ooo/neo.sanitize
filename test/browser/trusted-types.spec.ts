import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { expect, test } from '@playwright/test'

test('TrustedHTML output works under CSP enforcement', async ({
  page,
  browserName,
}) => {
  test.skip(browserName !== 'chromium', 'Trusted Types are Chromium-only here')

  const moduleSource = await readFile(resolve('dist/index.js'), 'utf8')
  await page.setContent(
    '<meta http-equiv="Content-Security-Policy" ' +
      'content="require-trusted-types-for \'script\'; ' +
      'trusted-types neo-sanitize-test">' +
      '<div id="target"></div>'
  )

  const result = await page.evaluate(async (source) => {
    const moduleURL = URL.createObjectURL(
      new Blob([source], { type: 'text/javascript' })
    )

    try {
      const sanitizer = await import(moduleURL)
      const trustedTypesFactory = Reflect.get(
        globalThis,
        'trustedTypes'
      ) as {
        createPolicy(
          name: string,
          rules: { createHTML(input: string): string }
        ): { createHTML(input: string): object }
        isHTML(value: unknown): boolean
      }
      const target = document.querySelector('#target') as HTMLDivElement
      let rawStringBlocked = false
      try {
        target.innerHTML = '<p>raw string</p>'
      } catch {
        rawStringBlocked = true
      }

      const policy = trustedTypesFactory.createPolicy('neo-sanitize-test', {
        createHTML(input: string): string {
          return input
        },
      })
      const trusted = sanitizer.sanitizeToTrustedHTML(
        '<script>alert(1)</script><p onclick=alert(2)>safe</p>',
        policy,
        { detectMXSS: true }
      )
      target.innerHTML = trusted

      const iframe = document.createElement('iframe')
      document.body.append(iframe)
      const iframeWindow = iframe.contentWindow as Window & typeof globalThis
      const iframeDocument = iframe.contentDocument as Document
      const iframeTrustedTypesFactory = Reflect.get(
        iframeWindow,
        'trustedTypes'
      ) as typeof trustedTypesFactory
      const iframePolicy = iframeTrustedTypesFactory.createPolicy(
        'neo-sanitize-test',
        {
          createHTML(input: string): string {
            return input
          },
        }
      )
      const iframeTarget = iframeDocument.createElement('div')
      iframeDocument.body.append(iframeTarget)
      const iframeTrusted = sanitizer.sanitizeToTrustedHTML(
        '<img src=x onerror=alert(3)><strong>iframe</strong>',
        iframePolicy,
        {},
        {
          document: iframeDocument,
          DOMParser: iframeWindow.DOMParser,
        }
      )
      iframeTarget.innerHTML = iframeTrusted

      return {
        html: target.innerHTML,
        iframeHTML: iframeTarget.innerHTML,
        iframeIsTrustedHTML:
          iframeTrustedTypesFactory.isHTML(iframeTrusted),
        isTrustedHTML: trustedTypesFactory.isHTML(trusted),
        rawStringBlocked,
      }
    } finally {
      URL.revokeObjectURL(moduleURL)
    }
  }, moduleSource)

  expect(result.rawStringBlocked).toBe(true)
  expect(result.isTrustedHTML).toBe(true)
  expect(result.html).toBe('<p>safe</p>')
  expect(result.iframeIsTrustedHTML).toBe(true)
  expect(result.iframeHTML).toBe('<img src="x"><strong>iframe</strong>')
})
