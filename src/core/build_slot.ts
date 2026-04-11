import { HEADER_SIZE, buildAAD } from "../core/constants.ts"
import { buildHeader } from "../core/header.ts"
import { randomBytes } from "../crypto/random.ts"
import { withKey } from "../crypto/kdf.ts"
import { resolveScheme } from "../crypto/registry.ts"
import { normalizePassphrase } from "../passphrase/normalizer.ts"
import type { PassphraseMode } from "../crypto/schemes/types.ts"

export interface BuildSlotParams {
  passphrase: string
  data: Uint8Array
  slotIndex: number
  mode: PassphraseMode
  schemeId: number
  slotSize: number
}

export const buildSlot = async ({
  passphrase,
  data,
  slotIndex,
  mode,
  schemeId,
  slotSize
}: BuildSlotParams): Promise<Uint8Array> => {
  const scheme = resolveScheme(schemeId)
  const salt = randomBytes(16)
  const slotNonce = randomBytes(16)
  const nonce = randomBytes(scheme.nonceBytes)
  const writtenAtMs = Date.now()
  const norm = normalizePassphrase(passphrase)
  const header = buildHeader({
    magic: new Uint8Array([0xDE, 0xC0, 0x1A, 0x57]),
    version: 0x01,
    schemeId,
    salt,
    nonce: scheme.nonceBytes === 12 ? nonce : nonce.subarray(0, 12),
    payloadLen: data.length,
    writtenAtMs,
    slotNonce
  })
  const aad = buildAAD(slotIndex, schemeId)
  return await withKey(
    scheme.deriveKey(norm + String.fromCharCode(...slotNonce), salt, mode),
    async (key: Uint8Array) => {
      const { ciphertext, tag } = await scheme.encrypt(key, nonce, data, aad)
      let offset = HEADER_SIZE
      const slotBuf = new Uint8Array(slotSize)
      slotBuf.set(header, 0)
      if (scheme.nonceBytes > 12) {
        slotBuf.set(nonce, offset)
        offset += scheme.nonceBytes
      }
      slotBuf.set(ciphertext, offset)
      slotBuf.set(tag, offset + ciphertext.length)
      const padStart = offset + ciphertext.length + tag.length
      if (padStart < slotBuf.length) {
        slotBuf.set(randomBytes(slotBuf.length - padStart), padStart)
      }
      return slotBuf
    }
  )
}
