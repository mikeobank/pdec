import { assert, assertEquals, assertThrows } from "@std/assert"
import { deriveAddress, rangesOverlap, resolveCollision } from "../src/core/addressing.ts"
import { deriveAddressMaterial } from "../src/crypto/kdf.ts"
import { buildEnvelope, parseEnvelope } from "../src/core/envelope.ts"
import { BLOCK_ALIGN, MAX_CIPHERTEXT_SIZE, MAX_COLLISION_RETRIES, MIN_FILE_SIZE, PLAINTEXT_ENVELOPE_SIZE } from "../src/core/constants.ts"
import { CollisionError, DecryptionFailedError, VersionMismatchError } from "../src/errors.ts"
import { randomBytes } from "../src/crypto/random.ts"

const TOTAL_SIZE = MIN_FILE_SIZE

Deno.test("deriveAddress: same passphrase produces same address and key", () => {
  const r1 = deriveAddress("samePassphrase!", TOTAL_SIZE)
  const r2 = deriveAddress("samePassphrase!", TOTAL_SIZE)
  assertEquals(r1.address, r2.address)
  assertEquals(r1.encryptionKey, r2.encryptionKey)
  r1.encryptionKey.fill(0)
  r2.encryptionKey.fill(0)
})

Deno.test("deriveAddress: different passphrases produce different addresses", () => {
  const r1 = deriveAddress("passphraseAAA!", TOTAL_SIZE)
  const r2 = deriveAddress("passphraseBBB!", TOTAL_SIZE)
  assert(r1.address !== r2.address || !r1.encryptionKey.every((b, i) => b === r2.encryptionKey[i]))
  r1.encryptionKey.fill(0)
  r2.encryptionKey.fill(0)
})

Deno.test("deriveAddress: address is within [0, totalSize - MAX_CIPHERTEXT_SIZE)", () => {
  const r = deriveAddress("addressRangeTest!", TOTAL_SIZE)
  assert(r.address >= 0)
  assert(r.address < TOTAL_SIZE - MAX_CIPHERTEXT_SIZE)
  r.encryptionKey.fill(0)
})

Deno.test("deriveAddress: address is aligned to BLOCK_ALIGN bytes", () => {
  const r = deriveAddress("alignmentTest!!", TOTAL_SIZE)
  assertEquals(r.address % BLOCK_ALIGN, 0)
  r.encryptionKey.fill(0)
})

Deno.test("deriveAddress: retryIndex 1 produces address offset by MAX_CIPHERTEXT_SIZE", () => {
  const r0 = deriveAddress("retryOffsetTest!", TOTAL_SIZE, 0)
  const r1 = deriveAddress("retryOffsetTest!", TOTAL_SIZE, 1)
  const addressableRange = TOTAL_SIZE - MAX_CIPHERTEXT_SIZE
  const alignedRange = Math.floor(addressableRange / BLOCK_ALIGN) * BLOCK_ALIGN
  const expected = Math.floor(((r0.baseAddress + MAX_CIPHERTEXT_SIZE) % alignedRange) / BLOCK_ALIGN) * BLOCK_ALIGN
  assertEquals(r1.address, expected)
  r0.encryptionKey.fill(0)
  r1.encryptionKey.fill(0)
})

Deno.test("deriveAddress: PIN mode uses higher Argon2id cost than unicode mode", () => {
  const pinMaterial = deriveAddressMaterial("12345", "pin")
  const unicodeMaterial = deriveAddressMaterial("12345", "unicode")
  assert(!pinMaterial.every((b, i) => b === unicodeMaterial[i]))
  pinMaterial.fill(0)
  unicodeMaterial.fill(0)
})

Deno.test("rangesOverlap: returns true for overlapping ranges", () => {
  assert(rangesOverlap(0, 0))
  assert(rangesOverlap(0, MAX_CIPHERTEXT_SIZE - 1))
  assert(rangesOverlap(MAX_CIPHERTEXT_SIZE - 1, 0))
})

Deno.test("rangesOverlap: returns false for adjacent non-overlapping ranges", () => {
  assert(!rangesOverlap(0, MAX_CIPHERTEXT_SIZE))
  assert(!rangesOverlap(MAX_CIPHERTEXT_SIZE, 0))
  assert(!rangesOverlap(0, MAX_CIPHERTEXT_SIZE * 2))
})

Deno.test("resolveCollision: finds non-overlapping address when base collides", () => {
  const r0 = deriveAddress("collisionTest!!!", TOTAL_SIZE, 0)
  const baseAddr = r0.baseAddress
  r0.encryptionKey.fill(0)
  const resolved = resolveCollision("collisionTest!!!", TOTAL_SIZE, [baseAddr])
  assert(resolved.address !== baseAddr)
  assert(!rangesOverlap(resolved.address, baseAddr))
  assertEquals(resolved.retryIndex, 1)
  resolved.encryptionKey.fill(0)
})

Deno.test("resolveCollision: throws CollisionError after MAX_COLLISION_RETRIES", () => {
  const r0 = deriveAddress("collisionExhaust!", TOTAL_SIZE, 0)
  const base = r0.baseAddress
  r0.encryptionKey.fill(0)

  const addressableRange = TOTAL_SIZE - MAX_CIPHERTEXT_SIZE
  const alignedRange = Math.floor(addressableRange / BLOCK_ALIGN) * BLOCK_ALIGN
  const allRetries: number[] = []
  for (let k = 0; k <= MAX_COLLISION_RETRIES; k++) {
    const addr = k === 0 ? base : Math.floor(((base + k * MAX_CIPHERTEXT_SIZE) % alignedRange) / BLOCK_ALIGN) * BLOCK_ALIGN
    allRetries.push(addr)
  }
  assertThrows(() => resolveCollision("collisionExhaust!", TOTAL_SIZE, allRetries), CollisionError)
})

Deno.test("buildEnvelope: round-trip with parseEnvelope returns original payload", () => {
  const payload = randomBytes(100)
  const envelope = buildEnvelope(
    { magic: new Uint8Array(4), version: 0x02, schemeId: 0x01, payloadLen: payload.length, writtenAtMs: 1234567890, retryIndex: 0, payload },
    PLAINTEXT_ENVELOPE_SIZE
  )
  const parsed = parseEnvelope(envelope)
  assertEquals(parsed.payload, payload)
  assertEquals(parsed.schemeId, 0x01)
  assertEquals(parsed.writtenAtMs, 1234567890)
  assertEquals(parsed.retryIndex, 0)
})

Deno.test("buildEnvelope: output is always PLAINTEXT_ENVELOPE_SIZE bytes", () => {
  const payload = randomBytes(50)
  const envelope = buildEnvelope(
    { magic: new Uint8Array(4), version: 0x02, schemeId: 0x01, payloadLen: payload.length, writtenAtMs: 0, retryIndex: 0, payload },
    PLAINTEXT_ENVELOPE_SIZE
  )
  assertEquals(envelope.length, PLAINTEXT_ENVELOPE_SIZE)
})

Deno.test("buildEnvelope: padding is random (two calls differ in padding bytes)", () => {
  const payload = randomBytes(32)
  const makeData = () => ({ magic: new Uint8Array(4), version: 0x02 as const, schemeId: 0x01, payloadLen: payload.length, writtenAtMs: 0, retryIndex: 0, payload })
  const e1 = buildEnvelope(makeData(), PLAINTEXT_ENVELOPE_SIZE)
  const e2 = buildEnvelope(makeData(), PLAINTEXT_ENVELOPE_SIZE)
  const padStart = 24 + payload.length
  const pad1 = e1.subarray(padStart)
  const pad2 = e2.subarray(padStart)
  assert(!pad1.every((b, i) => b === pad2[i]))
})

Deno.test("parseEnvelope: wrong magic after decryption throws DecryptionFailedError", () => {
  const payload = randomBytes(10)
  const envelope = buildEnvelope(
    { magic: new Uint8Array(4), version: 0x02, schemeId: 0x01, payloadLen: payload.length, writtenAtMs: 0, retryIndex: 0, payload },
    PLAINTEXT_ENVELOPE_SIZE
  )
  envelope[0] = 0xFF
  assertThrows(() => parseEnvelope(envelope), DecryptionFailedError)
})

Deno.test("parseEnvelope: version 0x01 throws VersionMismatchError", () => {
  const payload = randomBytes(10)
  const envelope = buildEnvelope(
    { magic: new Uint8Array(4), version: 0x02, schemeId: 0x01, payloadLen: payload.length, writtenAtMs: 0, retryIndex: 0, payload },
    PLAINTEXT_ENVELOPE_SIZE
  )
  envelope[4] = 0x01
  assertThrows(() => parseEnvelope(envelope), VersionMismatchError)
})

