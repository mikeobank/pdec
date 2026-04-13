import { xchacha20poly1305 } from "@noble/ciphers/chacha"
import { createArgon2KDF } from "../kdf.ts"
import type { EncryptResult, ICryptoScheme } from "./types.ts"
import { DecryptionFailedError } from "../../errors.ts"

/**
 * XChaCha20-Poly1305 + Argon2id (scheme 0x02)
 */
export const XChaCha20Argon2 = {
  id: 0x02,
  name: "XChaCha20-Poly1305+Argon2id",
  keyBytes: 32,
  nonceBytes: 24,
  tagBytes: 16,
  forceMode: "unicode" as const,

  deriveKey: createArgon2KDF(
    { m: 262144, t: 10, p: 1, dkLen: 32 }, // pin
    { m: 65536, t: 3, p: 1, dkLen: 32 } // unicode
  ),

  encrypt: (key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<EncryptResult> => {
    const cipher = xchacha20poly1305(key, nonce, aad)
    const out = cipher.encrypt(plaintext)
    const tagBytes = 16
    const ciphertext = out.subarray(0, out.length - tagBytes)
    const tag = out.subarray(out.length - tagBytes)
    return Promise.resolve({ ciphertext, tag })
  },

  decrypt: (key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, aad: Uint8Array): Promise<Uint8Array> => {
    try {
      const cipher = xchacha20poly1305(key, nonce, aad)
      const ct = new Uint8Array(ciphertext.length + tag.length)
      ct.set(ciphertext, 0)
      ct.set(tag, ciphertext.length)
      return Promise.resolve(cipher.decrypt(ct))
    } catch (_error) {
      return Promise.reject(new DecryptionFailedError())
    }
  }
} satisfies ICryptoScheme
