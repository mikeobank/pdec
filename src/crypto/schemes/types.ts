import type { PassphraseMode } from "../../passphrase/validator.ts"
export type { PassphraseMode } from "../../passphrase/validator.ts"

/**
 * AEAD encryption result.
 */
export interface EncryptResult {
  readonly ciphertext: Uint8Array
  readonly tag: Uint8Array
}

/**
 * Cryptographic scheme interface (plain object, not class).
 */
export interface ICryptoScheme {
  readonly id: number
  readonly name: string
  readonly keyBytes: number
  readonly nonceBytes: number
  readonly tagBytes: number
  readonly plaintextEnvelopeSize: number
  readonly forceMode?: PassphraseMode
  readonly deriveKey: (
    passphrase: Uint8Array,
    salt: Uint8Array,
    mode: PassphraseMode
  ) => Uint8Array
  readonly encrypt: (
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array
  ) => Promise<EncryptResult>
  readonly decrypt: (
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    tag: Uint8Array,
    aad: Uint8Array
  ) => Promise<Uint8Array>
}
