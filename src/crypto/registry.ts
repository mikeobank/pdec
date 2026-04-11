import { AES256GCMArgon2 } from "./schemes/aes256-gcm-argon2.ts"
import { XChaCha20Argon2 } from "./schemes/xchacha20-argon2.ts"
import { AES256GCMScrypt } from "./schemes/aes256-gcm-scrypt.ts"
import type { ICryptoScheme } from "./schemes/types.ts"
import { UnknownSchemeError } from "../errors.ts"

const _registry = new Map<number, ICryptoScheme>([
  [AES256GCMArgon2.id, AES256GCMArgon2],
  [XChaCha20Argon2.id, XChaCha20Argon2],
  [AES256GCMScrypt.id, AES256GCMScrypt]
])

/**
 * Resolve a scheme by ID. Throws UnknownSchemeError if not registered.
 */
export const resolveScheme = (id: number): ICryptoScheme => {
  const scheme = _registry.get(id)
  if (scheme === undefined) throw new UnknownSchemeError()
  return scheme
}

/**
 * Register a custom scheme. Throws if ID already registered.
 */
export const registerScheme = (scheme: ICryptoScheme): void => {
  if (_registry.has(scheme.id)) throw new UnknownSchemeError()
  _registry.set(scheme.id, scheme)
}
