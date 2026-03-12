/**
 * Sanitization Performance Benchmarks
 *
 * Compares @lpm.dev/neo.sanitize vs:
 * - DOMPurify (most popular, 23M downloads/week)
 * - sanitize-html (server-side, 2.5M downloads/week)
 */

import { bench, describe } from 'vitest'
import { sanitize as neoSanitize } from '../../src/core/sanitizer.js'
import DOMPurify from 'dompurify'
import sanitizeHtml from 'sanitize-html'
import { JSDOM } from 'jsdom'

// Setup DOMPurify for Node.js (needs jsdom)
const window = new JSDOM('').window
const DOMPurifyInstance = DOMPurify(window as unknown as Window)

// Test inputs
const SMALL_HTML = '<p>Hello <strong>world</strong>!</p>'

const MEDIUM_HTML = `
<div class="container">
  <h1>Blog Post Title</h1>
  <p>This is a <strong>blog post</strong> with <em>formatting</em>.</p>
  <p>It has <a href="https://example.com">links</a> and <img src="/image.jpg" alt="Image"></p>
  <ul>
    <li>Item 1</li>
    <li>Item 2</li>
    <li>Item 3</li>
  </ul>
</div>
`

const LARGE_HTML = `
<article>
  <header>
    <h1>Article Title</h1>
    <p class="meta">Posted on <time datetime="2024-01-01">January 1, 2024</time></p>
  </header>
  <section>
    <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
    <p>Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
    <blockquote>
      <p>Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.</p>
    </blockquote>
    <p>Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
    <h2>Subsection</h2>
    <p>More content with <a href="https://example.com">links</a> and <strong>bold text</strong>.</p>
    <pre><code class="language-javascript">
function hello() {
  console.log("Hello world");
}
</code></pre>
    <table>
      <thead>
        <tr>
          <th>Column 1</th>
          <th>Column 2</th>
          <th>Column 3</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Data 1</td>
          <td>Data 2</td>
          <td>Data 3</td>
        </tr>
        <tr>
          <td>Data 4</td>
          <td>Data 5</td>
          <td>Data 6</td>
        </tr>
      </tbody>
    </table>
  </section>
</article>
`

const XSS_HTML = '<p>Safe text</p><script>alert("XSS")</script><img src=x onerror="alert(1)"><a href="javascript:alert(2)">Click</a>'

describe('Small HTML (~50 chars)', () => {
  bench('neo.sanitize', () => {
    neoSanitize(SMALL_HTML)
  })

  bench('DOMPurify', () => {
    DOMPurifyInstance.sanitize(SMALL_HTML)
  })

  bench('sanitize-html', () => {
    sanitizeHtml(SMALL_HTML)
  })
})

describe('Medium HTML (~300 chars)', () => {
  bench('neo.sanitize', () => {
    neoSanitize(MEDIUM_HTML)
  })

  bench('DOMPurify', () => {
    DOMPurifyInstance.sanitize(MEDIUM_HTML)
  })

  bench('sanitize-html', () => {
    sanitizeHtml(MEDIUM_HTML)
  })
})

describe('Large HTML (~1.5 KB)', () => {
  bench('neo.sanitize', () => {
    neoSanitize(LARGE_HTML)
  })

  bench('DOMPurify', () => {
    DOMPurifyInstance.sanitize(LARGE_HTML)
  })

  bench('sanitize-html', () => {
    sanitizeHtml(LARGE_HTML)
  })
})

describe('HTML with XSS vectors', () => {
  bench('neo.sanitize', () => {
    neoSanitize(XSS_HTML)
  })

  bench('DOMPurify', () => {
    DOMPurifyInstance.sanitize(XSS_HTML)
  })

  bench('sanitize-html', () => {
    sanitizeHtml(XSS_HTML)
  })
})

describe('High-volume (1000 small HTML)', () => {
  bench('neo.sanitize', () => {
    for (let i = 0; i < 1000; i++) {
      neoSanitize(SMALL_HTML)
    }
  })

  bench('DOMPurify', () => {
    for (let i = 0; i < 1000; i++) {
      DOMPurifyInstance.sanitize(SMALL_HTML)
    }
  })

  bench('sanitize-html', () => {
    for (let i = 0; i < 1000; i++) {
      sanitizeHtml(SMALL_HTML)
    }
  })
})
