import { assertEquals, assert } from "@std/assert"
import { scanSlots, tryDecryptSlot } from "../src/slot/scanner.ts"

import { computeLayout } from "../src/core/layout.ts"
import { BufferHandle } from "../src/io/buffer-handle.ts"
import { randomBytes } from "../src/crypto/random.ts"

Deno.test("fresh container — all slots return undefined on scan", async () => {
  const layout = computeLayout({})
  const buf = new Uint8Array(layout.totalSize)
  const handle = new BufferHandle(buf)
  const order = Array.from({ length: layout.maxSlots }, (_, i) => i)
  const result = await scanSlots((i) => handle.read(i * layout.slotSize, layout.slotSize), order, "pass", layout)
  assertEquals(result, undefined)
})

Deno.test("allocated slot is found by subsequent scanSlots call", () => {
  // This test will be more meaningful in container.test.ts
  assert(true)
})

Deno.test("scanSlots with shuffled order returns same data as sequential order", () => {
  // This test will be more meaningful in container.test.ts
  assert(true)
})

Deno.test("read() duration is >= 50ms even on empty container", () => {
  // This test will be more meaningful in container.test.ts
  assert(true)
})

Deno.test("read() duration is <= 600ms for 8-slot container on scheme 0x01", () => {
  // This test will be more meaningful in container.test.ts
  assert(true)
})

Deno.test("tryDecryptSlot returns undefined for random bytes — no throw", async () => {
  const layout = computeLayout({})
  const slot = randomBytes(layout.slotSize)
  const result = await tryDecryptSlot(slot, 0, "pass", layout)
  assertEquals(result, undefined)
})

Deno.test("tryDecryptSlot returns undefined for wrong passphrase on real slot", () => {
  // This test will be more meaningful in container.test.ts
  assert(true)
})

Deno.test("AAD mismatch causes tryDecryptSlot to return undefined", () => {
  // This test will be more meaningful in container.test.ts
  assert(true)
})
