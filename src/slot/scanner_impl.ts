import type { SlotHeader } from "../core/header.ts"
import { parseHeader } from "../core/header.ts"
import { resolveScheme } from "../crypto/registry.ts"
import { buildAAD, HEADER_SIZE, MAGIC } from "../core/constants.ts"
import { normalizePassphrase } from "../passphrase/normalizer.ts"
import { detectPassphraseMode } from "../passphrase/validator.ts"
import { withKey } from "../crypto/kdf.ts"

/**
 * Internal implementation for tryDecryptSlot.
 */
export const tryDecryptSlot = async (
  slotBytes: Uint8Array,
  slotIndex: number,
  passphrase: string
): Promise<import("./scanner.ts").ScanResult | undefined> => {
  if (slotBytes.length < HEADER_SIZE) return undefined
  const headerBytes = slotBytes.subarray(0, HEADER_SIZE)
  let header: SlotHeader
  try {
    header = parseHeader(headerBytes)
  } catch {
    return undefined
  }
  let scheme
  try {
    scheme = resolveScheme(header.schemeId)
  } catch {
    return undefined
  }
  const aad = buildAAD(slotIndex, header.schemeId)
  const kdfInput = normalizePassphrase(passphrase)
  const mode = scheme.forceMode ?? detectPassphraseMode(passphrase)
  let plaintext: Uint8Array
  try {
    plaintext = await withKey(
      (() => {
        const passBytes = new TextEncoder().encode(kdfInput)
        const nonceCombined = new Uint8Array(passBytes.length + header.slotNonce.length)
        nonceCombined.set(passBytes, 0)
        nonceCombined.set(header.slotNonce, passBytes.length)
        return scheme.deriveKey(nonceCombined, header.salt, mode)
      })(),
      async (key: Uint8Array) => {
        let offset = HEADER_SIZE
        let nonce = header.nonce
        if (scheme.nonceBytes > 12) {
          nonce = slotBytes.subarray(offset, offset + scheme.nonceBytes)
          offset += scheme.nonceBytes
        }
        const ct = slotBytes.subarray(offset, offset + header.payloadLen)
        const tag = slotBytes.subarray(offset + header.payloadLen, offset + header.payloadLen + scheme.tagBytes)
        return await scheme.decrypt(key, nonce, ct, tag, aad)
      }
    )
  } catch {
    return undefined
  }
  if (!header.magic.every((b, i) => b === MAGIC[i])) return undefined
  return {
    slotIndex,
    header,
    payload: plaintext
  }
}
