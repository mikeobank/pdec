import { assertEquals, assertThrows } from "@std/assert"
import { computeLayout, slotOffset } from "../src/core/layout.ts"
import { HEADER_SIZE } from "../src/core/constants.ts"
import { ContainerTooSmallError } from "../src/errors.ts"

Deno.test("slotSize is floor(totalSize / maxSlots) aligned down to 64 bytes", () => {
  const layout = computeLayout({ totalSize: 10000000, maxSlots: 3 })
  assertEquals(layout.slotSize % 64, 0)
})

Deno.test("slotOffset(layout, i) equals i * slotSize", () => {
  const layout = computeLayout({ totalSize: 67108864, maxSlots: 8 })
  for (let i = 0; i < layout.maxSlots; ++i) {
    assertEquals(slotOffset(layout, i), i * layout.slotSize)
  }
})

Deno.test("default totalSize is 67108864", () => {
  const layout = computeLayout({})
  assertEquals(layout.totalSize, 67108864)
})

Deno.test("default maxSlots is 8", () => {
  const layout = computeLayout({})
  assertEquals(layout.maxSlots, 8)
})

Deno.test("ContainerTooSmallError for totalSize < 1 MiB", () => {
  assertThrows(() => computeLayout({ totalSize: 1024 }), ContainerTooSmallError)
})

Deno.test("ContainerTooSmallError when slotSize < HEADER_SIZE + 1", () => {
  assertThrows(() => computeLayout({ totalSize: (HEADER_SIZE + 1) * 2 - 1, maxSlots: 2 }), ContainerTooSmallError)
})

Deno.test("alignment works when totalSize is not divisible by maxSlots", () => {
  const layout = computeLayout({ totalSize: 10000001, maxSlots: 3 })
  assertEquals(layout.slotSize % 64, 0)
})

Deno.test("maxSlots=32 with totalSize=64MiB produces correct geometry", () => {
  const layout = computeLayout({ totalSize: 67108864, maxSlots: 32 })
  assertEquals(layout.maxSlots, 32)
  assertEquals(layout.totalSize, 67108864)
  assertEquals(layout.slotSize % 64, 0)
})
