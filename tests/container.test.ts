import { assertEquals, assertRejects, assert } from "@std/assert"
import { PDECContainer } from "../src/core/container.ts"
import { BufferHandle } from "../src/io/buffer-handle.ts"
import { computeLayout } from "../src/core/layout.ts"
import { randomBytes } from "../src/crypto/random.ts"
import { ContainerFullError } from "../src/errors.ts"

function makeContainer(layoutOverrides = {}): PDECContainer {
  const layout = computeLayout(layoutOverrides)
  const buf = new Uint8Array(layout.totalSize)
  const handle = new BufferHandle(buf)
  // @ts-ignore: _fromHandle is intentionally not exported from mod.ts
  return PDECContainer._fromHandle(handle, layout)
}

Deno.test("write and read round-trip — scheme 0x01 AES-GCM+Argon2id", async () => {
  const c = makeContainer()
  const data = randomBytes(32)
  await c.write("password123", data, { scheme: 0x01 })
  const slot = await c.read("password123")
  assert(slot)
  assertEquals(slot?.data, data)
  assertEquals(slot?.schemeId, 0x01)
})

Deno.test("write and read round-trip — scheme 0x02 XChaCha20+Argon2id", async () => {
  const c = makeContainer()
  const data = randomBytes(32)
  await c.write("password123", data, { scheme: 0x02 })
  const slot = await c.read("password123")
  assert(slot)
  assertEquals(slot?.data, data)
  assertEquals(slot?.schemeId, 0x02)
})

Deno.test("write and read round-trip — scheme 0x03 AES-GCM+scrypt", async () => {
  const c = makeContainer()
  const data = randomBytes(32)
  await c.write("password123", data, { scheme: 0x03 })
  const slot = await c.read("password123")
  assert(slot)
  assertEquals(slot?.data, data)
  assertEquals(slot?.schemeId, 0x03)
})

Deno.test("read returns undefined for wrong passphrase", async () => {
  const c = makeContainer()
  await c.write("password123", randomBytes(32))
  const slot = await c.read("wrongpass")
  assertEquals(slot, undefined)
})

Deno.test("read returns undefined on completely empty container", async () => {
  const c = makeContainer()
  const slot = await c.read("password123")
  assertEquals(slot, undefined)
})

Deno.test("wipe makes slot unreadable — returns undefined on subsequent read", async () => {
  const c = makeContainer()
  await c.write("password123", randomBytes(32))
  const wiped = await c.wipe("password123")
  assert(wiped)
  const slot = await c.read("password123")
  assertEquals(slot, undefined)
})

Deno.test("wipe returns false when passphrase has no slot", async () => {
  const c = makeContainer()
  const wiped = await c.wipe("password123")
  assertEquals(wiped, false)
})

Deno.test("two slots are independently accessible", async () => {
  const c = makeContainer()
  const data1 = randomBytes(32)
  const data2 = randomBytes(32)
  await c.write("password123", data1)
  await c.write("password456", data2)
  const slot1 = await c.read("password123")
  const slot2 = await c.read("password456")
  assertEquals(slot1?.data, data1)
  assertEquals(slot2?.data, data2)
})

Deno.test("overwriting a slot preserves all other slots", async () => {
  const c = makeContainer()
  const data1 = randomBytes(32)
  const data2 = randomBytes(32)
  await c.write("password123", data1)
  await c.write("password456", data2)
  await c.write("password123", data2)
  const slot1 = await c.read("password123")
  const slot2 = await c.read("password456")
  assertEquals(slot1?.data, data2)
  assertEquals(slot2?.data, data2)
})

Deno.test("write with 5-digit PIN passphrase succeeds", async () => {
  // Inject a fast test KDF for Argon2id
  const { AES256GCMArgon2 } = await import("../src/crypto/schemes/aes256-gcm-argon2.ts")
  const origKDF = AES256GCMArgon2.deriveKey
  AES256GCMArgon2.deriveKey = (await import("../src/crypto/kdf.ts")).createArgon2KDF(
    { m: 8, t: 1, p: 1, dkLen: 32 },
    { m: 8, t: 1, p: 1, dkLen: 32 }
  )
  try {
    const c = makeContainer()
    const data = randomBytes(32)
    await c.write("12345", data)
    const slot = await c.read("12345")
    assert(slot)
    assertEquals(slot?.data, data)
  } finally {
    AES256GCMArgon2.deriveKey = origKDF
  }
})

Deno.test("write with Unicode passphrase containing emoji succeeds", async () => {
  const c = makeContainer()
  const data = randomBytes(32)
  await c.write("😀😃😄😁😆😅😂🤣", data)
  const slot = await c.read("😀😃😄😁😆😅😂🤣")
  assert(slot)
  assertEquals(slot?.data, data)
})

Deno.test("write with Unicode passphrase containing CJK characters succeeds", async () => {
  const c = makeContainer()
  const data = randomBytes(32)
  await c.write("漢字仮名交じり文", data)
  const slot = await c.read("漢字仮名交じり文")
  assert(slot)
  assertEquals(slot?.data, data)
})

Deno.test("write with Unicode passphrase containing RTL characters succeeds", async () => {
  const c = makeContainer()
  const data = randomBytes(32)
  await c.write("مرحباالعالم", data)
  const slot = await c.read("مرحباالعالم")
  assert(slot)
  assertEquals(slot?.data, data)
})

Deno.test("container with maxSlots=1 works correctly", async () => {
  const c = makeContainer({ maxSlots: 1 })
  const data = randomBytes(32)
  await c.write("password123", data)
  const slot = await c.read("password123")
  assert(slot)
  assertEquals(slot?.data, data)
})

Deno.test("ContainerFullError thrown when all slots are occupied", async () => {
  const c = makeContainer({ maxSlots: 1 })
  await c.write("password123", randomBytes(32))
  await assertRejects(() => c.write("password456", randomBytes(32)), ContainerFullError)
})

Deno.test("forceNewSlot allocates additional slot instead of overwriting", async () => {
  const c = makeContainer({ maxSlots: 2 })
  const data1 = randomBytes(32)
  const data2 = randomBytes(32)
  await c.write("password123", data1)
  await c.write("password123", data2, { forceNewSlot: true })
  const slot = await c.read("password123")
  assert(slot)
  assertEquals(slot?.data, data2)
})

Deno.test("SlotData.writtenAt is within 5 seconds of current time", async () => {
  const c = makeContainer()
  const data = randomBytes(32)
  await c.write("password123", data)
  const slot = await c.read("password123")
  assert(slot)
  const now = Date.now()
  assert(Math.abs(slot!.writtenAt.getTime() - now) < 5000)
})

Deno.test("SlotData.schemeId matches the scheme used to write", async () => {
  const c = makeContainer()
  const data = randomBytes(32)
  await c.write("password123", data, { scheme: 0x02 })
  const slot = await c.read("password123")
  assert(slot)
  assertEquals(slot?.schemeId, 0x02)
})
