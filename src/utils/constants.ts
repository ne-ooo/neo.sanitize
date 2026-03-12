/**
 * @lpm.dev/neo.sanitize - Constants
 *
 * Predefined lists of allowed/forbidden tags, attributes, and protocols.
 * Based on OWASP guidelines and common XSS attack vectors.
 */

/**
 * Default allowed HTML tags (safe for basic formatting)
 *
 * Covers common formatting needs while blocking dangerous tags like:
 * - <script>, <iframe>, <object>, <embed> (code execution)
 * - <style>, <link> (CSS injection)
 * - <form>, <input>, <button> (phishing, CSRF)
 * - <base> (URL hijacking)
 */
export const DEFAULT_ALLOWED_TAGS: readonly string[] = [
  // Text formatting
  'p',
  'br',
  'span',
  'div',
  'blockquote',
  'pre',
  'code',

  // Headings
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',

  // Text styling
  'strong',
  'b',
  'em',
  'i',
  'u',
  's',
  'del',
  'ins',
  'mark',
  'small',
  'sub',
  'sup',

  // Lists
  'ul',
  'ol',
  'li',
  'dl',
  'dt',
  'dd',

  // Links and images
  'a',
  'img',

  // Tables
  'table',
  'thead',
  'tbody',
  'tfoot',
  'tr',
  'th',
  'td',
  'caption',
  'colgroup',
  'col',

  // Quotes and citations
  'q',
  'cite',
  'abbr',
  'time',

  // Code blocks
  'samp',
  'kbd',
  'var',

  // Figures
  'figure',
  'figcaption',

  // Horizontal rule
  'hr',
] as const

/**
 * Default allowed attributes per tag
 *
 * Only safe attributes that don't allow code execution:
 * - href/src: Protocol validation required
 * - alt/title: Safe text content
 * - class/id: Only if explicitly enabled
 */
export const DEFAULT_ALLOWED_ATTRIBUTES: Readonly<Record<string, readonly string[]>> = {
  a: ['href', 'title', 'rel', 'target'],
  img: ['src', 'alt', 'title', 'width', 'height'],
  table: ['width', 'border', 'cellpadding', 'cellspacing'],
  td: ['colspan', 'rowspan', 'align', 'valign'],
  th: ['colspan', 'rowspan', 'align', 'valign', 'scope'],
  code: ['class'], // for syntax highlighting (e.g., class="language-js")
  pre: ['class'], // for syntax highlighting
  blockquote: ['cite'],
  q: ['cite'],
  time: ['datetime'],
  abbr: ['title'],
  col: ['span', 'width'],
  colgroup: ['span', 'width'],
} as const

/**
 * Forbidden attributes (always removed, regardless of tag)
 *
 * Blocks all event handlers and dangerous attributes:
 * - Event handlers: onclick, onerror, onload, etc. (XSS vectors)
 * - Script-related: onfocus, onblur, onchange, etc.
 * - Form-related: onsubmit, onreset, etc.
 */
export const FORBIDDEN_ATTRIBUTES: readonly string[] = [
  // Mouse events
  'onclick',
  'ondblclick',
  'onmousedown',
  'onmouseup',
  'onmousemove',
  'onmouseover',
  'onmouseout',
  'onmouseenter',
  'onmouseleave',
  'oncontextmenu',

  // Keyboard events
  'onkeydown',
  'onkeyup',
  'onkeypress',

  // Form events
  'onsubmit',
  'onreset',
  'onchange',
  'oninput',
  'oninvalid',
  'onfocus',
  'onblur',
  'onselect',

  // Media events
  'onplay',
  'onpause',
  'onplaying',
  'onended',
  'onerror',
  'onloadstart',
  'onloadeddata',
  'onloadedmetadata',
  'oncanplay',
  'oncanplaythrough',
  'ontimeupdate',
  'onvolumechange',
  'onwaiting',
  'onseeking',
  'onseeked',
  'onabort',
  'onemptied',
  'onstalled',
  'onsuspend',
  'ondurationchange',
  'onratechange',

  // Window/frame events
  'onload',
  'onunload',
  'onbeforeunload',
  'onresize',
  'onscroll',
  'onhashchange',
  'onpopstate',
  'onpageshow',
  'onpagehide',

  // Drag events
  'ondrag',
  'ondragstart',
  'ondragend',
  'ondragenter',
  'ondragleave',
  'ondragover',
  'ondrop',

  // Clipboard events
  'oncopy',
  'oncut',
  'onpaste',

  // Print events
  'onbeforeprint',
  'onafterprint',

  // Animation events
  'onanimationstart',
  'onanimationend',
  'onanimationiteration',

  // Transition events
  'ontransitionstart',
  'ontransitionend',
  'ontransitionrun',
  'ontransitioncancel',

  // Other dangerous attributes
  'onwheel',
  'ongotpointercapture',
  'onlostpointercapture',
  'onpointercancel',
  'onpointerdown',
  'onpointerenter',
  'onpointerleave',
  'onpointermove',
  'onpointerout',
  'onpointerover',
  'onpointerup',
  'ontouchstart',
  'ontouchmove',
  'ontouchend',
  'ontouchcancel',

  // Dangerous non-event attributes
  'formaction', // Can redirect form submission
  'action', // Form action URL
  'data', // <object> data URL
  'ping', // <a> ping tracking
] as const

/**
 * Allowed URL protocols for href, src, and similar attributes
 *
 * Only safe protocols that don't allow code execution:
 * - http/https: Web URLs
 * - mailto: Email links
 * - tel: Phone links
 * - ftp: File transfer (safe in href context)
 *
 * Blocked protocols:
 * - javascript: Direct code execution
 * - data: Can contain HTML/scripts
 * - vbscript: VBScript execution (IE)
 * - file: Local file access
 * - about: Browser internals
 */
export const ALLOWED_PROTOCOLS: readonly string[] = [
  'http',
  'https',
  'mailto',
  'tel',
  'ftp',
  'ftps',
] as const

/**
 * Dangerous URL protocols (always blocked)
 *
 * These protocols allow code execution or data injection:
 * - javascript: Executes JavaScript code
 * - data: Can contain HTML, SVG, scripts
 * - vbscript: Executes VBScript (legacy IE)
 * - about: Access to browser internals
 * - file: Access to local file system
 */
export const DANGEROUS_PROTOCOLS: readonly string[] = [
  'javascript',
  'data',
  'vbscript',
  'about',
  'file',
] as const

/**
 * Void elements (self-closing, have no content)
 *
 * These elements cannot have child nodes:
 * - <br>, <hr>, <img>, <input>, etc.
 *
 * Important for parsing and serialization.
 */
export const VOID_ELEMENTS: readonly string[] = [
  'area',
  'base',
  'br',
  'col',
  'embed',
  'hr',
  'img',
  'input',
  'link',
  'meta',
  'param',
  'source',
  'track',
  'wbr',
] as const

/**
 * Attributes that accept URLs and require protocol validation
 *
 * These attributes can be vectors for javascript:, data:, etc.:
 * - href: Links (<a>, <area>, <link>)
 * - src: Resources (<img>, <script>, <iframe>, <embed>, etc.)
 * - action: Form submissions
 * - formaction: Button/input form actions
 * - cite: Blockquote/q citations
 * - data: Object data
 * - poster: Video posters
 */
export const URL_ATTRIBUTES: readonly string[] = [
  'href',
  'src',
  'action',
  'formaction',
  'cite',
  'data',
  'poster',
  'background',
  'lowsrc',
  'ping',
  'srcset',
] as const

/**
 * Regular expression to match event handler attributes
 *
 * Matches any attribute starting with "on" followed by letters:
 * - onclick, onerror, onload, etc.
 *
 * Used as fallback if event handler is not in FORBIDDEN_ATTRIBUTES list.
 */
export const EVENT_HANDLER_REGEX = /^on\w+$/i

/**
 * Regular expression to match data-* attributes
 *
 * Matches any attribute starting with "data-":
 * - data-id, data-value, data-test, etc.
 *
 * Generally safe, but can be used for client-side tracking.
 */
export const DATA_ATTRIBUTE_REGEX = /^data-[\w-]+$/i

/**
 * Regular expression to match aria-* attributes
 *
 * Matches any attribute starting with "aria-":
 * - aria-label, aria-hidden, aria-describedby, etc.
 *
 * Safe and important for accessibility.
 */
export const ARIA_ATTRIBUTE_REGEX = /^aria-[\w-]+$/i

/**
 * HTML entities for escaping dangerous characters
 *
 * Used when stripping tags but keeping text content.
 */
export const HTML_ENTITIES: Readonly<Record<string, string>> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '/': '&#x2F;',
} as const
