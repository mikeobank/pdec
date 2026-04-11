/**
 * Passphrase mode: 'pin' or 'unicode'.
 */
export type PassphraseMode = "pin" | "unicode"

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
  readonly deriveKey: (
    passphrase: string,
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
