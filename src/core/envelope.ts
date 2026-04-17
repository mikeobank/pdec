import { DOMAIN_MAGIC, VERSION } from "./constants.ts"
import { randomBytes } from "../crypto/random.ts"
import { DecryptionFailedError, VersionMismatchError } from "../errors.ts"

export interface EnvelopeData {
  readonly magic: Uint8Array
  readonly version: number
  readonly schemeId: number
  readonly payloadLen: number
  readonly writtenAtMs: number
  readonly retryIndex: number
  readonly payload: Uint8Array
}

export const buildEnvelope = (data: EnvelopeData, envelopeSize: number): Uint8Array => {
  const buf = new Uint8Array(envelopeSize)
  const view = new DataView(buf.buffer)
  buf.set(DOMAIN_MAGIC, 0)
  buf[4] = VERSION & 0xFF
  buf[5] = data.schemeId & 0xFF
  buf[6] = 0
  buf[7] = 0
  view.setUint32(8, data.payloadLen, true)
  view.setUint32(12, data.writtenAtMs & 0xFFFFFFFF, true)
  view.setUint32(16, Math.floor(data.writtenAtMs / 0x100000000), true)
  view.setUint32(20, data.retryIndex, true)
  buf.set(data.payload.subarray(0, data.payloadLen), 24)
  const padStart = 24 + data.payloadLen
  if (padStart < envelopeSize) {
    buf.set(randomBytes(envelopeSize - padStart), padStart)
  }
  return buf
}

export const parseEnvelope = (bytes: Uint8Array): EnvelopeData => {
  if (bytes[4] !== VERSION) throw new VersionMismatchError(bytes[4]!)
  if (!DOMAIN_MAGIC.every((b, i) => b === bytes[i])) throw new DecryptionFailedError()
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const schemeId = bytes[5]!
  const payloadLen = view.getUint32(8, true)
  const writtenAtMs = view.getUint32(12, true) + 0x100000000 * view.getUint32(16, true)
  const retryIndex = view.getUint32(20, true)
  const payload = bytes.slice(24, 24 + payloadLen)
  return {
    magic: bytes.slice(0, 4),
    version: VERSION,
    schemeId,
    payloadLen,
    writtenAtMs,
    retryIndex,
    payload
  }
}
