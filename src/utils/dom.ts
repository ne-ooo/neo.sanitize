/**
 * Read a DOM property from its prototype descriptor. HTML named-property
 * access can otherwise shadow properties such as parentNode on form elements.
 */
function unavailableDOMMethod(methodName: PropertyKey): never {
  throw new TypeError(`DOM method ${String(methodName)} is not available.`)
}

interface DOMIntrinsics {
  appendChild: Function
  attributeName: Function
  attributeValue: Function
  attributes: Function
  attributesItem: Function
  attributesLength: Function
  body: Function
  childNodes: Function
  childNodesItem: Function
  childNodesLength: Function
  cloneNode: Function
  createDocumentFragment: Function
  createElement: Function
  firstChild: Function
  hasAttribute: Function
  innerHTMLGet: Function
  innerHTMLSet: Function
  insertBefore: Function
  lastChild: Function
  localName: Function
  namespaceURI: Function
  nextSibling: Function
  nodeType: Function
  ownerDocument: Function
  parentNode: Function
  removeAttribute: Function
  removeChild: Function
  reliableNextSibling: boolean
  setAttribute: Function
}

const APPLY = Reflect.apply
const NO_ARGUMENTS: [] = []
const DOM_INTRINSICS_CACHE = new WeakMap<object, DOMIntrinsics>()
let activeDOMIntrinsics: DOMIntrinsics | undefined

function capturePrototypeFunction(
  target: object,
  property: PropertyKey,
  kind: 'get' | 'set' | 'method'
): Function {
  let prototype = Object.getPrototypeOf(target) as object | null

  while (prototype) {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, property)
    const operation =
      kind === 'get'
        ? descriptor?.get
        : kind === 'set'
          ? descriptor?.set
          : descriptor?.value
    if (typeof operation === 'function') return operation
    prototype = Object.getPrototypeOf(prototype) as object | null
  }

  if (kind === 'method') {
    const own = Object.getOwnPropertyDescriptor(target, property)?.value
    if (typeof own === 'function') return own
  }

  throw new TypeError(
    `DOM ${kind === 'method' ? 'method' : 'property'} ${String(property)} is not available.`
  )
}

/** Capture a DOM method without using an own-property collision. */
export function captureDOMMethod(
  target: object,
  property: PropertyKey
): Function {
  return capturePrototypeFunction(target, property, 'method')
}

function captureDOMIntrinsics(document: Document): DOMIntrinsics {
  const createElement = capturePrototypeFunction(
    document,
    'createElement',
    'method'
  )
  const element = APPLY(createElement, document, ['div']) as HTMLElement
  const appendChild = capturePrototypeFunction(element, 'appendChild', 'method')
  const attributes = capturePrototypeFunction(element, 'attributes', 'get')
  const childNodes = capturePrototypeFunction(element, 'childNodes', 'get')
  const firstChild = capturePrototypeFunction(element, 'firstChild', 'get')
  const lastChild = capturePrototypeFunction(element, 'lastChild', 'get')
  const nextSibling = capturePrototypeFunction(element, 'nextSibling', 'get')
  const setAttribute = capturePrototypeFunction(element, 'setAttribute', 'method')
  APPLY(setAttribute, element, ['data-neo-intrinsics', 'probe'])
  const attributeMap = APPLY(
    attributes,
    element,
    NO_ARGUMENTS
  ) as NamedNodeMap
  const attributesItem = capturePrototypeFunction(
    attributeMap,
    'item',
    'method'
  )
  const probeAttribute = APPLY(attributesItem, attributeMap, [0]) as Attr | null
  if (!probeAttribute) {
    throw new TypeError('DOM attributes are not available.')
  }
  const firstProbe = APPLY(createElement, document, ['i']) as HTMLElement
  const secondProbe = APPLY(createElement, document, ['b']) as HTMLElement
  APPLY(appendChild, element, [firstProbe])
  APPLY(appendChild, element, [secondProbe])
  const reliableNextSibling =
    APPLY(firstChild, element, NO_ARGUMENTS) === firstProbe &&
    APPLY(nextSibling, firstProbe, NO_ARGUMENTS) === secondProbe &&
    APPLY(lastChild, element, NO_ARGUMENTS) === secondProbe
  const childNodeList = APPLY(childNodes, element, NO_ARGUMENTS) as NodeListOf<ChildNode>

  return Object.freeze({
    appendChild,
    attributeName: capturePrototypeFunction(probeAttribute, 'name', 'get'),
    attributeValue: capturePrototypeFunction(probeAttribute, 'value', 'get'),
    attributes,
    attributesItem,
    attributesLength: capturePrototypeFunction(attributeMap, 'length', 'get'),
    body: capturePrototypeFunction(document, 'body', 'get'),
    childNodes,
    childNodesItem: capturePrototypeFunction(childNodeList, 'item', 'method'),
    childNodesLength: capturePrototypeFunction(childNodeList, 'length', 'get'),
    cloneNode: capturePrototypeFunction(element, 'cloneNode', 'method'),
    createDocumentFragment: capturePrototypeFunction(
      document,
      'createDocumentFragment',
      'method'
    ),
    createElement,
    firstChild,
    hasAttribute: capturePrototypeFunction(element, 'hasAttribute', 'method'),
    innerHTMLGet: capturePrototypeFunction(element, 'innerHTML', 'get'),
    innerHTMLSet: capturePrototypeFunction(element, 'innerHTML', 'set'),
    insertBefore: capturePrototypeFunction(element, 'insertBefore', 'method'),
    lastChild,
    localName: capturePrototypeFunction(element, 'localName', 'get'),
    namespaceURI: capturePrototypeFunction(element, 'namespaceURI', 'get'),
    nextSibling,
    nodeType: capturePrototypeFunction(element, 'nodeType', 'get'),
    ownerDocument: capturePrototypeFunction(element, 'ownerDocument', 'get'),
    parentNode: capturePrototypeFunction(element, 'parentNode', 'get'),
    removeAttribute: capturePrototypeFunction(element, 'removeAttribute', 'method'),
    removeChild: capturePrototypeFunction(element, 'removeChild', 'method'),
    reliableNextSibling,
    setAttribute,
  })
}

/** Run synchronous DOM work with runtime-specific prototype operations. */
export function withDOMIntrinsics<T>(
  document: Document,
  operation: () => T
): T {
  const cacheKey = Object.getPrototypeOf(document) as object | null
  let intrinsics = DOM_INTRINSICS_CACHE.get(cacheKey ?? document)
  if (!intrinsics) {
    intrinsics = captureDOMIntrinsics(document)
    DOM_INTRINSICS_CACHE.set(cacheKey ?? document, intrinsics)
  }

  const previous = activeDOMIntrinsics
  activeDOMIntrinsics = intrinsics
  try {
    return operation()
  } finally {
    activeDOMIntrinsics = previous
  }
}

/** Whether the active runtime passed its one-time sibling traversal probe. */
export function hasReliableDOMSiblingTraversal(): boolean {
  return activeDOMIntrinsics?.reliableNextSibling === true
}

export function readDOMProperty<T>(target: object, property: PropertyKey): T {
  if (!Object.prototype.hasOwnProperty.call(target, property)) {
    return Reflect.get(target, property) as T
  }

  let prototype = Object.getPrototypeOf(target) as object | null

  while (prototype) {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, property)
    if (descriptor?.get) {
      const getter = descriptor.get
      return Reflect.apply(getter, target, []) as T
    }
    prototype = Object.getPrototypeOf(prototype) as object | null
  }

  return Reflect.get(target, property) as T
}

export function callDOMMethod<T>(
  target: object,
  methodName: PropertyKey,
  args: unknown[]
): T {
  const own = Object.getOwnPropertyDescriptor(target, methodName)
  if (!own) {
    const method = Reflect.get(target, methodName) as unknown
    if (typeof method === 'function') return Reflect.apply(method, target, args) as T
    unavailableDOMMethod(methodName)
  }

  let prototype = Object.getPrototypeOf(target) as object | null

  while (prototype) {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, methodName)
    if (typeof descriptor?.value === 'function') {
      return Reflect.apply(descriptor.value, target, args) as T
    }
    prototype = Object.getPrototypeOf(prototype) as object | null
  }

  if (typeof own.value === 'function') {
    return Reflect.apply(own.value, target, args) as T
  }
  unavailableDOMMethod(methodName)
}

export function getFirstChild(node: Node): ChildNode | null {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.firstChild, node, NO_ARGUMENTS) as ChildNode | null
  }
  return readDOMProperty<ChildNode | null>(node, 'firstChild')
}

export function getNextSibling(node: Node): ChildNode | null {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.nextSibling, node, NO_ARGUMENTS) as ChildNode | null
  }
  return readDOMProperty<ChildNode | null>(node, 'nextSibling')
}

export function getLastChild(node: Node): ChildNode | null {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.lastChild, node, NO_ARGUMENTS) as ChildNode | null
  }
  return readDOMProperty<ChildNode | null>(node, 'lastChild')
}

export function getChildNodes(node: Node): NodeListOf<ChildNode> {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.childNodes, node, NO_ARGUMENTS) as NodeListOf<ChildNode>
  }
  return readDOMProperty<NodeListOf<ChildNode>>(node, 'childNodes')
}

export function copyChildNodes(nodes: NodeListOf<ChildNode>): ChildNode[] {
  const copy: ChildNode[] = []
  const length = activeDOMIntrinsics
    ? (APPLY(
        activeDOMIntrinsics.childNodesLength,
        nodes,
        NO_ARGUMENTS
      ) as number)
    : readDOMProperty<number>(nodes, 'length')

  for (let index = 0; index < length; index++) {
    const child = activeDOMIntrinsics
      ? (APPLY(activeDOMIntrinsics.childNodesItem, nodes, [index]) as ChildNode | null)
      : callDOMMethod<ChildNode | null>(nodes, 'item', [index])
    if (child) copy.push(child)
  }
  return copy
}

export function getNodeType(node: Node): number {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.nodeType, node, NO_ARGUMENTS) as number
  }
  return readDOMProperty<number>(node, 'nodeType')
}

export function getElementLocalName(element: Element): string {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.localName, element, NO_ARGUMENTS) as string
  }
  return readDOMProperty<string>(element, 'localName')
}

export function getElementNamespace(element: Element): string | null {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.namespaceURI, element, NO_ARGUMENTS) as string | null
  }
  return readDOMProperty<string | null>(element, 'namespaceURI')
}

export function getOwnerDocument(node: Node): Document {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.ownerDocument, node, NO_ARGUMENTS) as Document
  }
  return readDOMProperty<Document>(node, 'ownerDocument')
}

export function getDocumentBody(document: Document): HTMLBodyElement | null {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.body, document, NO_ARGUMENTS) as HTMLBodyElement | null
  }
  return readDOMProperty<HTMLBodyElement | null>(document, 'body')
}

export function getElementAttributes(element: Element): NamedNodeMap {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.attributes, element, NO_ARGUMENTS) as NamedNodeMap
  }
  return readDOMProperty<NamedNodeMap>(element, 'attributes')
}

export function getAttributeMapLength(attributes: NamedNodeMap): number {
  if (activeDOMIntrinsics) {
    return APPLY(
      activeDOMIntrinsics.attributesLength,
      attributes,
      NO_ARGUMENTS
    ) as number
  }
  return readDOMProperty<number>(attributes, 'length')
}

export function getAttributeAt(
  attributes: NamedNodeMap,
  index: number
): Attr | null {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.attributesItem, attributes, [index]) as Attr | null
  }
  return callDOMMethod<Attr | null>(attributes, 'item', [index])
}

export function getAttributeName(attribute: Attr): string {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.attributeName, attribute, NO_ARGUMENTS) as string
  }
  return readDOMProperty<string>(attribute, 'name')
}

export function getAttributeValue(attribute: Attr): string {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.attributeValue, attribute, NO_ARGUMENTS) as string
  }
  return readDOMProperty<string>(attribute, 'value')
}

export function hasElementAttribute(element: Element, name: string): boolean {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.hasAttribute, element, [name]) as boolean
  }
  return callDOMMethod<boolean>(element, 'hasAttribute', [name])
}

export function cloneDOMNode<T extends Node>(node: T, deep: boolean): T {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.cloneNode, node, [deep]) as T
  }
  return callDOMMethod<T>(node, 'cloneNode', [deep])
}

export function appendNode(parent: Node, node: Node): Node {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.appendChild, parent, [node]) as Node
  }
  return callDOMMethod<Node>(parent, 'appendChild', [node])
}

export function createDocumentFragment(document: Document): DocumentFragment {
  if (activeDOMIntrinsics) {
    return APPLY(
      activeDOMIntrinsics.createDocumentFragment,
      document,
      NO_ARGUMENTS
    ) as DocumentFragment
  }
  return callDOMMethod<DocumentFragment>(document, 'createDocumentFragment', [])
}

export function createElement(document: Document, name: string): HTMLElement {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.createElement, document, [
      name,
    ]) as HTMLElement
  }
  return callDOMMethod<HTMLElement>(document, 'createElement', [name])
}

export function setElementHTML(element: Element, html: string | object): void {
  if (activeDOMIntrinsics) {
    APPLY(activeDOMIntrinsics.innerHTMLSet, element, [html])
    return
  }

  let prototype = Object.getPrototypeOf(element) as object | null

  while (prototype) {
    const setter = Object.getOwnPropertyDescriptor(prototype, 'innerHTML')?.set
    if (setter) {
      Reflect.apply(setter, element, [html])
      return
    }
    prototype = Object.getPrototypeOf(prototype) as object | null
  }

  throw new TypeError('DOM innerHTML setter is not available.')
}

export function getElementHTML(element: Element): string {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.innerHTMLGet, element, NO_ARGUMENTS) as string
  }
  return readDOMProperty<string>(element, 'innerHTML')
}

export function removeElementAttribute(element: Element, name: string): void {
  if (activeDOMIntrinsics) {
    APPLY(activeDOMIntrinsics.removeAttribute, element, [name])
    return
  }
  callDOMMethod<void>(element, 'removeAttribute', [name])
}

export function setElementAttribute(
  element: Element,
  name: string,
  value: string
): void {
  if (activeDOMIntrinsics) {
    APPLY(activeDOMIntrinsics.setAttribute, element, [name, value])
    return
  }
  callDOMMethod<void>(element, 'setAttribute', [name, value])
}

export function getParentNode(node: Node): ParentNode | null {
  if (activeDOMIntrinsics) {
    return APPLY(activeDOMIntrinsics.parentNode, node, NO_ARGUMENTS) as ParentNode | null
  }
  return readDOMProperty<ParentNode | null>(node, 'parentNode')
}

export function removeNode(node: Node): void {
  const parent = getParentNode(node)
  if (!parent) return
  if (activeDOMIntrinsics) {
    APPLY(activeDOMIntrinsics.removeChild, parent, [node])
    return
  }
  callDOMMethod<Node>(parent, 'removeChild', [node])
}

export function insertBeforeNode(
  parent: Node,
  node: Node,
  reference: Node
): void {
  if (activeDOMIntrinsics) {
    APPLY(activeDOMIntrinsics.insertBefore, parent, [node, reference])
    return
  }
  callDOMMethod<Node>(parent, 'insertBefore', [node, reference])
}
