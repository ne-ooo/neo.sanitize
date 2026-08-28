import type {
  TrustedHTMLLike,
  TrustedTypePolicyLike,
} from '../types.js'
import { readDOMProperty } from './dom.js'

interface TrustedTypesFactoryLike {
  isHTML(value: unknown): boolean
}

export interface TrustedHTMLAdapter<
  TTrustedHTML extends TrustedHTMLLike = TrustedHTMLLike,
> {
  createHTML(value: string): TTrustedHTML
}

export class TrustedTypesIntegrationError extends TypeError {
  constructor(message: string, options?: ErrorOptions) {
    super(`@lpm.dev/neo.sanitize: ${message}`, options)
    this.name = 'TrustedTypesIntegrationError'
  }
}

function getCallable(target: object, property: PropertyKey): Function | undefined {
  const value = Reflect.get(target, property) as unknown
  return typeof value === 'function' ? value : undefined
}

/** Create a validated identity adapter for browser Trusted Types sinks. */
export function createTrustedHTMLAdapter<
  TTrustedHTML extends TrustedHTMLLike,
>(
  policy: TrustedTypePolicyLike<TTrustedHTML>,
  document: Document
): TrustedHTMLAdapter<TTrustedHTML> {
  const view = readDOMProperty<object | null>(document, 'defaultView')
  const realmFactory = view
    ? (Reflect.get(view, 'trustedTypes') as unknown)
    : undefined
  const globalDocument = Reflect.get(globalThis as object, 'document') as unknown
  const factoryValue =
    realmFactory ??
    (globalDocument === document
      ? (Reflect.get(globalThis as object, 'trustedTypes') as unknown)
      : undefined)
  if (typeof factoryValue !== 'object' || factoryValue === null) {
    throw new TrustedTypesIntegrationError(
      'Trusted Types are not available in this environment. Use sanitize() for a string result.'
    )
  }

  const factory = factoryValue as TrustedTypesFactoryLike
  const isHTML = getCallable(factory, 'isHTML')
  if (!isHTML) {
    throw new TrustedTypesIntegrationError(
      'The Trusted Types factory does not expose isHTML().'
    )
  }

  if (typeof policy !== 'object' || policy === null) {
    throw new TrustedTypesIntegrationError(
      'Pass a TrustedTypePolicy with a createHTML() method.'
    )
  }

  const createHTML = getCallable(policy, 'createHTML')
  if (!createHTML) {
    throw new TrustedTypesIntegrationError(
      'Pass a TrustedTypePolicy with a createHTML() method.'
    )
  }

  return {
    createHTML(value: string): TTrustedHTML {
      let trustedHTML: TTrustedHTML
      try {
        trustedHTML = Reflect.apply(createHTML, policy, [value]) as TTrustedHTML
      } catch (cause) {
        throw new TrustedTypesIntegrationError(
          'The Trusted Types policy rejected HTML conversion.',
          { cause }
        )
      }

      let accepted = false
      try {
        accepted = Boolean(Reflect.apply(isHTML, factory, [trustedHTML]))
      } catch (cause) {
        throw new TrustedTypesIntegrationError(
          'The Trusted Types factory failed to validate the policy result.',
          { cause }
        )
      }
      if (!accepted) {
        throw new TrustedTypesIntegrationError(
          'The policy createHTML() method did not return TrustedHTML.'
        )
      }

      let serialized: string
      try {
        serialized = String(trustedHTML)
      } catch (cause) {
        throw new TrustedTypesIntegrationError(
          'The TrustedHTML result could not be serialized for identity validation.',
          { cause }
        )
      }
      if (serialized !== value) {
        throw new TrustedTypesIntegrationError(
          'The Trusted Types policy must preserve its input unchanged.'
        )
      }

      return trustedHTML
    },
  }
}
