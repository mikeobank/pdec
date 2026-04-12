import { HEADER_SIZE, MAGIC, buildAAD } from "../core/constants.ts"
import { buildHeader } from "../core/header.ts"
import { randomBytes } from "../crypto/random.ts"
import { withKey } from "../crypto/kdf.ts"
import { normalizePassphrase } from "../passphrase/normalizer.ts"
import type { PassphraseMode } from "../crypto/schemes/types.ts"
import type { ICryptoScheme } from "../crypto/schemes/types.ts"
import { PayloadTooLargeError } from "../errors.ts"

export interface BuildSlotParams {
  passphrase: string
  data: Uint8Array
  slotIndex: number
  mode: PassphraseMode
  scheme: ICryptoScheme
  slotSize: number
}

export const buildSlot = async ({
  passphrase,
  data,
  slotIndex,
  mode,
  scheme,
  slotSize
}: BuildSlotParams): Promise<Uint8Array> => {
  const schemeId = scheme.id
  const nonceInBody = scheme.nonceBytes > 12 ? scheme.nonceBytes : 0
  const requiredSize = HEADER_SIZE + nonceInBody + data.length + scheme.tagBytes
  if (requiredSize > slotSize) {
    throw new PayloadTooLargeError(requiredSize, slotSize)
  }
  const salt = randomBytes(16)
  const slotNonce = randomBytes(16)
  const nonce = randomBytes(scheme.nonceBytes)
  const writtenAtMs = Date.now()
  const norm = normalizePassphrase(passphrase)
  const header = buildHeader({
    magic: MAGIC,
    version: 0x01,
    schemeId,
    allocated: 1,
    salt,
    nonce: scheme.nonceBytes === 12 ? nonce : nonce.subarray(0, 12),
    payloadLen: data.length,
    writtenAtMs,
    slotNonce
  })
  const aad = buildAAD(slotIndex, schemeId)
  return await withKey(
    (() => {
      const passBytes = new TextEncoder().encode(norm)
      const kdfInput = new Uint8Array(passBytes.length + slotNonce.length)
      kdfInput.set(passBytes, 0)
      kdfInput.set(slotNonce, passBytes.length)
      return scheme.deriveKey(kdfInput, salt, mode)
    })(),
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
