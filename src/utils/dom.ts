/**
 * Read a DOM property from its prototype descriptor. HTML named-property
 * access can otherwise shadow properties such as parentNode on form elements.
 */
function unavailableDOMMethod(methodName: PropertyKey): never {
  throw new TypeError(`DOM method ${String(methodName)} is not available.`)
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
  return readDOMProperty<ChildNode | null>(node, 'firstChild')
}

export function getNextSibling(node: Node): ChildNode | null {
  return readDOMProperty<ChildNode | null>(node, 'nextSibling')
}

export function getLastChild(node: Node): ChildNode | null {
  return readDOMProperty<ChildNode | null>(node, 'lastChild')
}

export function getChildNodes(node: Node): NodeListOf<ChildNode> {
  return readDOMProperty<NodeListOf<ChildNode>>(node, 'childNodes')
}

export function getNodeType(node: Node): number {
  return readDOMProperty<number>(node, 'nodeType')
}

export function getElementLocalName(element: Element): string {
  return readDOMProperty<string>(element, 'localName')
}

export function getElementNamespace(element: Element): string | null {
  return readDOMProperty<string | null>(element, 'namespaceURI')
}

export function getOwnerDocument(node: Node): Document {
  return readDOMProperty<Document>(node, 'ownerDocument')
}

export function getDocumentBody(document: Document): HTMLBodyElement | null {
  return readDOMProperty<HTMLBodyElement | null>(document, 'body')
}

export function getElementAttributes(element: Element): NamedNodeMap {
  return readDOMProperty<NamedNodeMap>(element, 'attributes')
}

export function hasElementAttribute(element: Element, name: string): boolean {
  return callDOMMethod<boolean>(element, 'hasAttribute', [name])
}

export function cloneDOMNode<T extends Node>(node: T, deep: boolean): T {
  return callDOMMethod<T>(node, 'cloneNode', [deep])
}

export function appendNode(parent: Node, node: Node): Node {
  return callDOMMethod<Node>(parent, 'appendChild', [node])
}

export function createDocumentFragment(document: Document): DocumentFragment {
  return callDOMMethod<DocumentFragment>(document, 'createDocumentFragment', [])
}

export function createElement(document: Document, name: string): HTMLElement {
  return callDOMMethod<HTMLElement>(document, 'createElement', [name])
}

export function removeElementAttribute(element: Element, name: string): void {
  callDOMMethod<void>(element, 'removeAttribute', [name])
}

export function setElementAttribute(
  element: Element,
  name: string,
  value: string
): void {
  callDOMMethod<void>(element, 'setAttribute', [name, value])
}

export function getParentNode(node: Node): ParentNode | null {
  return readDOMProperty<ParentNode | null>(node, 'parentNode')
}

export function removeNode(node: Node): void {
  const parent = getParentNode(node)
  if (parent) callDOMMethod<Node>(parent, 'removeChild', [node])
}

export function insertBeforeNode(
  parent: Node,
  node: Node,
  reference: Node
): void {
  callDOMMethod<Node>(parent, 'insertBefore', [node, reference])
}
