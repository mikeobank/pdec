import { assertEquals, assert } from "@std/assert"
import { validatePassphrase } from "../src/passphrase/validator.ts"
import { normalizePassphrase } from "../src/passphrase/normalizer.ts"

Deno.test("valid 5-digit PIN is accepted with mode=pin", () => {
  const result = validatePassphrase("12345")
  assert(result.valid)
  assertEquals(result.mode, "pin")
})

Deno.test("4-digit string is rejected", () => {
  const result = validatePassphrase("1234")
  assert(!result.valid)
  assert(result.errors.some(e => e.includes("All-digit")))
})

Deno.test("6-digit string is rejected", () => {
  const result = validatePassphrase("123456")
  assert(!result.valid)
  assert(result.errors.some(e => e.includes("All-digit")))
})

Deno.test("unicode password of exactly 8 codepoints is accepted", () => {
  const result = validatePassphrase("abcdefgh")
  assert(result.valid)
  assertEquals(result.mode, "unicode")
})

Deno.test("unicode password of 7 codepoints is rejected", () => {
  const result = validatePassphrase("abcdefg")
  assert(!result.valid)
  assert(result.errors.some(e => e.includes("at least 8 codepoints")))
})

Deno.test("8 emoji codepoints accepted — counts codepoints not UTF-16 units", () => {
  const result = validatePassphrase("😀😃😄😁😆😅😂🤣")
  assert(result.valid)
})

Deno.test("all-digit string of length >= 8 is rejected", () => {
  const result = validatePassphrase("12345678")
  assert(!result.valid)
  assert(result.errors.some(e => e.includes("All-digit")))
})

Deno.test("whitespace-only string of length 8 is rejected", () => {
  const result = validatePassphrase("        ")
  assert(!result.valid)
  assert(result.errors.some(e => e.includes("Whitespace-only")))
})

Deno.test("empty string is rejected", () => {
  const result = validatePassphrase("")
  assert(!result.valid)
  assert(result.errors.some(e => e.includes("at least 8 codepoints")))
})

Deno.test("PIN mode result includes a low-entropy warning", () => {
  const result = validatePassphrase("12345")
  assert(result.warnings.some((w) => w.includes("low entropy")))
})

Deno.test("NFC normalization: U+00E9 and e+U+0301 produce identical KDF input", () => {
  const a = normalizePassphrase("\u00e9")
  const b = normalizePassphrase("e\u0301")
  assertEquals(a, b)
})

Deno.test("normalizePassphrase is idempotent", () => {
  const a = normalizePassphrase("\u00e9")
  const b = normalizePassphrase(normalizePassphrase("\u00e9"))
  assertEquals(a, b)
})
