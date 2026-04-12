import { argon2id } from "@noble/hashes/argon2"
import { scrypt } from "@noble/hashes/scrypt"
import type { PassphraseMode } from "./schemes/types.ts"


export interface Argon2Params {
  m: number
  t: number
  p: number
  dkLen: number
}

export interface ScryptParams {
  N: number
  r: number
  p: number
  dkLen: number
}

export const createArgon2KDF = (
  paramsPin: Argon2Params,
  paramsUnicode: Argon2Params
): (passphrase: Uint8Array, salt: Uint8Array, mode: PassphraseMode) => Uint8Array => {
  return (passphrase: Uint8Array, salt: Uint8Array, mode: PassphraseMode): Uint8Array => {
    const params = mode === "pin" ? paramsPin : paramsUnicode
    return argon2id(passphrase, salt, params)
  }
}

export const createScryptKDF = (
  paramsPin: ScryptParams,
  paramsUnicode: ScryptParams
): (passphrase: Uint8Array, salt: Uint8Array, mode: PassphraseMode) => Uint8Array => {
  return (passphrase: Uint8Array, salt: Uint8Array, mode: PassphraseMode): Uint8Array => {
    const params = mode === "pin" ? paramsPin : paramsUnicode
    return scrypt(passphrase, salt, params)
  }
}

/**
 * Zero the key buffer in a finally block after fn completes or throws.
 * All encrypt/decrypt call sites must use this wrapper.
 */
export const withKey = async <T>(
  key: Uint8Array,
  fn: (key: Uint8Array) => Promise<T> | T
): Promise<T> => {
  try {
    return await fn(key)
  } finally {
    key.fill(0)
  }
}
