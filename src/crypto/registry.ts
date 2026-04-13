import { AES256GCMArgon2 } from "./schemes/aes256-gcm-argon2.ts"
import { XChaCha20Argon2 } from "./schemes/xchacha20-argon2.ts"
import { AES256GCMScrypt } from "./schemes/aes256-gcm-scrypt.ts"
import type { ICryptoScheme } from "./schemes/types.ts"
import { SchemeAlreadyRegisteredError, UnknownSchemeError } from "../errors.ts"

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
 * Register a custom scheme. Validates all parameters are within safe ranges.
 * Throws if ID already registered, out of valid range, or params are invalid.
 */
export const registerScheme = (scheme: ICryptoScheme): void => {
  if (scheme.id < 0 || scheme.id > 255 || !Number.isInteger(scheme.id)) {
    throw new Error("Scheme ID must be an integer in range 0..255")
  }
  if (scheme.keyBytes < 16 || scheme.keyBytes > 64) {
    throw new Error("keyBytes must be in range 16..64")
  }
  if (scheme.nonceBytes < 8 || scheme.nonceBytes > 32) {
    throw new Error("nonceBytes must be in range 8..32")
  }
  if (scheme.tagBytes < 12 || scheme.tagBytes > 32) {
    throw new Error("tagBytes must be in range 12..32")
  }
  if (typeof scheme.deriveKey !== "function" || typeof scheme.encrypt !== "function" || typeof scheme.decrypt !== "function") {
    throw new Error("Scheme must have deriveKey, encrypt, and decrypt methods")
  }
  if (_registry.has(scheme.id)) throw new SchemeAlreadyRegisteredError()
  _registry.set(scheme.id, scheme)
}
