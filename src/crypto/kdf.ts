import { argon2id } from "@noble/hashes/argon2"
import { scrypt } from "@noble/hashes/scrypt"
import type { PassphraseMode } from "./schemes/types.ts"
import { DOMAIN_SALT } from "../core/constants.ts"
import { normalizePassphrase } from "../passphrase/normalizer.ts"

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

const ARGON2_PARAMS_PIN: Argon2Params = { m: 262144, t: 10, p: 1, dkLen: 64 }
const ARGON2_PARAMS_UNICODE: Argon2Params = { m: 65536, t: 3, p: 1, dkLen: 64 }

export const deriveAddressMaterial = (passphrase: string, mode: PassphraseMode): Uint8Array => {
  const params = mode === "pin" ? ARGON2_PARAMS_PIN : ARGON2_PARAMS_UNICODE
  const passBytes = new TextEncoder().encode(normalizePassphrase(passphrase))
  return argon2id(passBytes, DOMAIN_SALT, params)
}
