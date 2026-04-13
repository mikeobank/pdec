import { assert, assertEquals } from "@std/assert"
import { scanSlots, tryDecryptSlot } from "../src/slot/scanner.ts"
import { computeLayout } from "../src/core/layout.ts"
import { BufferHandle } from "../src/io/buffer-handle.ts"
import { randomBytes } from "../src/crypto/random.ts"
import { buildSlot } from "../src/core/build_slot.ts"
import { PDECContainer } from "../src/core/container.ts"
import { AES256GCMArgon2 } from "../src/crypto/schemes/aes256-gcm-argon2.ts"
import { createArgon2KDF } from "../src/crypto/kdf.ts"
import { registerScheme, resolveScheme } from "../src/crypto/registry.ts"

const SLOT_TEST_SCHEME_ID = 0xA1
registerScheme({
  ...AES256GCMArgon2,
  id: SLOT_TEST_SCHEME_ID,
  name: "AES-256-GCM+Argon2id (slot test fast)",
  deriveKey: createArgon2KDF(
    { m: 8, t: 1, p: 1, dkLen: 32 },
    { m: 8, t: 1, p: 1, dkLen: 32 }
  )
})

const layout = computeLayout({ defaultScheme: SLOT_TEST_SCHEME_ID })

const makeHandle = (): BufferHandle => new BufferHandle(new Uint8Array(layout.totalSize))

Deno.test("fresh container — all slots return undefined on scan", async () => {
  const handle = makeHandle()
  const order = Array.from({ length: layout.maxSlots }, (_, i) => i)
  const result = await scanSlots((i) => handle.read(i * layout.slotSize, layout.slotSize), order, "pass")
  assertEquals(result, undefined)
})

Deno.test("allocated slot is found by subsequent scanSlots call", async () => {
  const handle = makeHandle()
  const data = randomBytes(32)
  const slotBuf = await buildSlot({
    passphrase: "password123",
    data,
    slotIndex: 0,
    mode: "unicode",
    scheme: resolveScheme(SLOT_TEST_SCHEME_ID),
    slotSize: layout.slotSize
  })
  await handle.write(0, slotBuf)
  const order = Array.from({ length: layout.maxSlots }, (_, i) => i)
  const result = await scanSlots((i) => handle.read(i * layout.slotSize, layout.slotSize), order, "password123")
  assert(result !== undefined)
  assertEquals(result.payload, data)
})

Deno.test("scanSlots with shuffled order returns same data as sequential order", async () => {
  const handle = makeHandle()
  const data = randomBytes(32)
  const slotBuf = await buildSlot({
    passphrase: "password123",
    data,
    slotIndex: 2,
    mode: "unicode",
    scheme: resolveScheme(SLOT_TEST_SCHEME_ID),
    slotSize: layout.slotSize
  })
  await handle.write(2 * layout.slotSize, slotBuf)
  const sequential = Array.from({ length: layout.maxSlots }, (_, i) => i)
  const shuffled = [4, 0, 7, 2, 5, 1, 3, 6]
  const r1 = await scanSlots((i) => handle.read(i * layout.slotSize, layout.slotSize), sequential, "password123")
  const r2 = await scanSlots((i) => handle.read(i * layout.slotSize, layout.slotSize), shuffled, "password123")
  assert(r1 !== undefined)
  assert(r2 !== undefined)
  assertEquals(r1.payload, data)
  assertEquals(r2.payload, data)
})

Deno.test("read() duration is >= 50ms even on empty container", async () => {
  const handle = makeHandle()
  // @ts-ignore: _fromHandle is intentionally not exported from mod.ts
  const c = PDECContainer._fromHandle(handle, layout)
  const start = Date.now()
  await c.read("password123")
  const elapsed = Date.now() - start
  assert(elapsed >= 50, `Expected >= 50ms, got ${elapsed}ms`)
})

Deno.test("tryDecryptSlot returns undefined for random bytes — no throw", async () => {
  const slot = randomBytes(layout.slotSize)
  const result = await tryDecryptSlot(slot, 0, "pass")
  assertEquals(result, undefined)
})

Deno.test("tryDecryptSlot returns undefined for wrong passphrase on real slot", async () => {
  const data = randomBytes(32)
  const slotBuf = await buildSlot({
    passphrase: "password123",
    data,
    slotIndex: 0,
    mode: "unicode",
    scheme: resolveScheme(SLOT_TEST_SCHEME_ID),
    slotSize: layout.slotSize
  })
  const result = await tryDecryptSlot(slotBuf, 0, "wrongpassword")
  assertEquals(result, undefined)
})

Deno.test("AAD mismatch causes tryDecryptSlot to return undefined", async () => {
  const data = randomBytes(32)
  const slotBuf = await buildSlot({
    passphrase: "password123",
    data,
    slotIndex: 0,
    mode: "unicode",
    scheme: resolveScheme(SLOT_TEST_SCHEME_ID),
    slotSize: layout.slotSize
  })
  const result = await tryDecryptSlot(slotBuf, 1, "password123")
  assertEquals(result, undefined)
})
