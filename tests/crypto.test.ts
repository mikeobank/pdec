import type { EncryptResult } from "../src/crypto/schemes/types.ts"
import { assert, assertEquals, assertRejects, assertThrows } from "@std/assert"
import { AES256GCMArgon2 } from "../src/crypto/schemes/aes256-gcm-argon2.ts"
import { XChaCha20Argon2 } from "../src/crypto/schemes/xchacha20-argon2.ts"
import { AES256GCMScrypt } from "../src/crypto/schemes/aes256-gcm-scrypt.ts"
import { createArgon2KDF, createScryptKDF, withKey } from "../src/crypto/kdf.ts"
import { registerScheme, resolveScheme } from "../src/crypto/registry.ts"
import { DecryptionFailedError, UnknownSchemeError } from "../src/errors.ts"

Deno.test("scheme 0x01: encrypt then decrypt returns original plaintext", async () => {
  const scheme = AES256GCMArgon2
  const key = scheme.deriveKey(new TextEncoder().encode("password"), new Uint8Array(16), "unicode")
  const nonce = new Uint8Array(scheme.nonceBytes)
  const aad = new Uint8Array([1, 2, 3, 4, 5, 6])
  const pt = new Uint8Array([1, 2, 3, 4, 5])
  const { ciphertext, tag } = await scheme.encrypt(key, nonce, pt, aad)
  const dec = await scheme.decrypt(key, nonce, ciphertext, tag, aad)
  assertEquals(dec, pt)
})

Deno.test("scheme 0x02: encrypt then decrypt returns original plaintext", async () => {
  const scheme = XChaCha20Argon2
  const key = scheme.deriveKey(new TextEncoder().encode("password"), new Uint8Array(16), "unicode")
  const nonce = new Uint8Array(scheme.nonceBytes)
  const aad = new Uint8Array([1, 2, 3, 4, 5, 6])
  const pt = new Uint8Array([1, 2, 3, 4, 5])
  const { ciphertext, tag } = await scheme.encrypt(key, nonce, pt, aad)
  const dec = await scheme.decrypt(key, nonce, ciphertext, tag, aad)
  assertEquals(dec, pt)
})

Deno.test("scheme 0x03: encrypt then decrypt returns original plaintext", async () => {
  const scheme = AES256GCMScrypt
  const key = scheme.deriveKey(new TextEncoder().encode("password"), new Uint8Array(16), "unicode")
  const nonce = new Uint8Array(scheme.nonceBytes)
  const aad = new Uint8Array([1, 2, 3, 4, 5, 6])
  const pt = new Uint8Array([1, 2, 3, 4, 5])
  const { ciphertext, tag } = await scheme.encrypt(key, nonce, pt, aad)
  const dec = await scheme.decrypt(key, nonce, ciphertext, tag, aad)
  assertEquals(dec, pt)
})

Deno.test("scheme 0x01: flipped ciphertext byte fails AEAD authentication", async () => {
  const scheme = AES256GCMArgon2
  const key = scheme.deriveKey(new TextEncoder().encode("password"), new Uint8Array(16), "unicode")
  const nonce = new Uint8Array(scheme.nonceBytes)
  const aad = new Uint8Array([1, 2, 3, 4, 5, 6])
  const pt = new Uint8Array([1, 2, 3, 4, 5])
  const result = await scheme.encrypt(key, nonce, pt, aad) as EncryptResult
  if (result.ciphertext === undefined) throw new Error("ciphertext is undefined")
  if (result.tag === undefined) throw new Error("tag is undefined")
  result.ciphertext[0] ^= 0xff
  await assertRejects(() => scheme.decrypt(key, nonce, result.ciphertext, result.tag, aad), DecryptionFailedError)
})

Deno.test("scheme 0x02: flipped ciphertext byte fails AEAD authentication", async () => {
  const scheme = XChaCha20Argon2
  const key = scheme.deriveKey(new TextEncoder().encode("password"), new Uint8Array(16), "unicode")
  const nonce = new Uint8Array(scheme.nonceBytes)
  const aad = new Uint8Array([1, 2, 3, 4, 5, 6])
  const pt = new Uint8Array([1, 2, 3, 4, 5])
  const result2 = await scheme.encrypt(key, nonce, pt, aad) as EncryptResult
  if (result2.ciphertext === undefined) throw new Error("ciphertext2 is undefined")
  if (result2.tag === undefined) throw new Error("tag2 is undefined")
  result2.ciphertext[0] ^= 0xff
  await assertRejects(() => scheme.decrypt(key, nonce, result2.ciphertext, result2.tag, aad), DecryptionFailedError)
})

Deno.test("scheme 0x03: flipped ciphertext byte fails AEAD authentication", async () => {
  const scheme = AES256GCMScrypt
  const key = scheme.deriveKey(new TextEncoder().encode("password"), new Uint8Array(16), "unicode")
  const nonce = new Uint8Array(scheme.nonceBytes)
  const aad = new Uint8Array([1, 2, 3, 4, 5, 6])
  const pt = new Uint8Array([1, 2, 3, 4, 5])
  const result3 = await scheme.encrypt(key, nonce, pt, aad) as EncryptResult
  if (result3.ciphertext === undefined) throw new Error("ciphertext3 is undefined")
  if (result3.tag === undefined) throw new Error("tag3 is undefined")
  result3.ciphertext[0] ^= 0xff
  await assertRejects(() => scheme.decrypt(key, nonce, result3.ciphertext, result3.tag, aad), DecryptionFailedError)
})

Deno.test("scheme 0x01: modified AAD fails AEAD authentication", async () => {
  const scheme = AES256GCMArgon2
  const key = scheme.deriveKey(new TextEncoder().encode("password"), new Uint8Array(16), "unicode")
  const nonce = new Uint8Array(scheme.nonceBytes)
  const aad = new Uint8Array([1, 2, 3, 4, 5, 6])
  const pt = new Uint8Array([1, 2, 3, 4, 5])
  const result4 = await scheme.encrypt(key, nonce, pt, aad) as EncryptResult
  if (result4.ciphertext === undefined) throw new Error("ciphertext4 is undefined")
  if (result4.tag === undefined) throw new Error("tag4 is undefined")
  if (aad === undefined) throw new Error("aad is undefined")
  aad[0] ^= 0xff
  await assertRejects(() => scheme.decrypt(key, nonce, result4.ciphertext, result4.tag, aad), DecryptionFailedError)
})

Deno.test("scheme 0x02: modified AAD fails AEAD authentication", async () => {
  const scheme = XChaCha20Argon2
  const key = scheme.deriveKey(new TextEncoder().encode("password"), new Uint8Array(16), "unicode")
  const nonce = new Uint8Array(scheme.nonceBytes)
  const aad = new Uint8Array([1, 2, 3, 4, 5, 6])
  const pt = new Uint8Array([1, 2, 3, 4, 5])
  const result5 = await scheme.encrypt(key, nonce, pt, aad) as EncryptResult
  if (result5.ciphertext === undefined) throw new Error("ciphertext5 is undefined")
  if (result5.tag === undefined) throw new Error("tag5 is undefined")
  if (aad === undefined) throw new Error("aad is undefined")
  aad[0] ^= 0xff
  await assertRejects(() => scheme.decrypt(key, nonce, result5.ciphertext, result5.tag, aad), DecryptionFailedError)
})

Deno.test("scheme 0x03: modified AAD fails AEAD authentication", async () => {
  const scheme = AES256GCMScrypt
  const key = scheme.deriveKey(new TextEncoder().encode("password"), new Uint8Array(16), "unicode")
  const nonce = new Uint8Array(scheme.nonceBytes)
  const aad = new Uint8Array([1, 2, 3, 4, 5, 6])
  const pt = new Uint8Array([1, 2, 3, 4, 5])
  const result6 = await scheme.encrypt(key, nonce, pt, aad) as EncryptResult
  if (result6.ciphertext === undefined) throw new Error("ciphertext6 is undefined")
  if (result6.tag === undefined) throw new Error("tag6 is undefined")
  if (aad === undefined) throw new Error("aad is undefined")
  aad[0] ^= 0xff
  await assertRejects(() => scheme.decrypt(key, nonce, result6.ciphertext, result6.tag, aad), DecryptionFailedError)
})

Deno.test("PIN mode uses higher Argon2id memory cost than unicode mode", () => {
  const testArgon2KDF = createArgon2KDF(
    { m: 64, t: 1, p: 1, dkLen: 32 },
    { m: 32, t: 1, p: 1, dkLen: 32 }
  )
  const passphrase = new Uint8Array([0x31, 0x32, 0x33, 0x34, 0x35])
  const salt = new Uint8Array(16)
  const pinKey = testArgon2KDF(passphrase, salt, "pin")
  const unicodeKey = testArgon2KDF(passphrase, salt, "unicode")
  assertEquals(pinKey.length, unicodeKey.length)
  assertEquals(pinKey.length, 32)
  assert(pinKey.some((b, i) => b !== unicodeKey[i]))
})

Deno.test("PIN mode uses higher scrypt N than unicode mode", () => {
  const testScryptKDF = createScryptKDF(
    { N: 32, r: 1, p: 1, dkLen: 32 },
    { N: 16, r: 1, p: 1, dkLen: 32 }
  )
  const passphrase = new Uint8Array([0x31, 0x32, 0x33, 0x34, 0x35])
  const salt = new Uint8Array(16)
  const pinKey = testScryptKDF(passphrase, salt, "pin")
  const unicodeKey = testScryptKDF(passphrase, salt, "unicode")
  assertEquals(pinKey.length, unicodeKey.length)
  assertEquals(pinKey.length, 32)
  assert(pinKey.some((b, i) => b !== unicodeKey[i]))
})

Deno.test("withKey zeroes key buffer after fn resolves successfully", async () => {
  const key = new Uint8Array([1, 2, 3, 4, 5])
  await withKey(key, (k) => {
    assertEquals(k, key)
    return undefined
  })
  assert(key.every((b) => b === 0))
})

Deno.test("withKey zeroes key buffer even when fn throws", async () => {
  const key = new Uint8Array([1, 2, 3, 4, 5])
  await assertRejects(() =>
    withKey(key, () => {
      throw new Error("fail")
    })
  )
  assert(key.every((b) => b === 0))
})

Deno.test("resolving unknown scheme ID throws UnknownSchemeError", () => {
  assertThrows(() => resolveScheme(0xff), UnknownSchemeError)
})

Deno.test("registerScheme adds a custom scheme resolvable by ID", () => {
  const custom = { ...AES256GCMArgon2, id: 0x42, name: "custom" }
  registerScheme(custom)
  assertEquals(resolveScheme(0x42).name, "custom")
})
