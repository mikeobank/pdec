import { createScryptKDF } from "../kdf.ts"
import type { ICryptoScheme, EncryptResult } from "./types.ts"
import { DecryptionFailedError } from "../../errors.ts"

/**
 * AES-256-GCM + scrypt (scheme 0x03)
 */
export const AES256GCMScrypt = {
  id: 0x03,
  name: "AES-256-GCM+scrypt",
  keyBytes: 32,
  nonceBytes: 12,
  tagBytes: 16,

  deriveKey: createScryptKDF(
    { N: 262144, r: 8, p: 2, dkLen: 32 }, // pin
    { N: 131072, r: 8, p: 1, dkLen: 32 }  // unicode
  ),

  encrypt: async (key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<EncryptResult> => {
    const algo = { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key.slice().buffer,
      algo,
      false,
      ["encrypt"]
    )
    const enc = await crypto.subtle.encrypt(
      algo,
      cryptoKey,
      plaintext.slice().buffer
    )
    const buf = new Uint8Array(enc)
    const tagBytes = 16
    const ciphertext = buf.subarray(0, buf.length - tagBytes)
    const tag = buf.subarray(buf.length - tagBytes)
    return { ciphertext, tag }
  },

  decrypt: async (key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, aad: Uint8Array): Promise<Uint8Array> => {
    try {
      const algo = { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key.slice().buffer,
        algo,
        false,
        ["decrypt"]
      )
      const ct = new Uint8Array(ciphertext.length + tag.length)
      ct.set(ciphertext, 0)
      ct.set(tag, ciphertext.length)
      const dec = await crypto.subtle.decrypt(
        algo,
        cryptoKey,
        ct.slice().buffer
      )
      return new Uint8Array(dec)
    } catch {
      throw new DecryptionFailedError()
    }
  }
} satisfies ICryptoScheme
