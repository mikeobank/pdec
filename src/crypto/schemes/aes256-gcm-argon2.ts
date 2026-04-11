import { createArgon2KDF } from "../kdf.ts"
import type { ICryptoScheme, EncryptResult } from "./types.ts"
import { DecryptionFailedError } from "../../errors.ts"

/**
 * AES-256-GCM + Argon2id (scheme 0x01)
 */
export const AES256GCMArgon2 = {
  id: 0x01,
  name: "AES-256-GCM+Argon2id",
  keyBytes: 32,
  nonceBytes: 12,
  tagBytes: 16,

  deriveKey: createArgon2KDF(
    { m: 262144, t: 10, p: 1, dkLen: 32 }, // pin
    { m: 65536, t: 3, p: 1, dkLen: 32 }   // unicode
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
    return { ciphertext, tag } as EncryptResult
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
