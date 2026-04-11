import { VERSION, HEADER_SIZE } from "./constants.ts"
import { VersionMismatchError } from "../errors.ts"

export class HeaderLengthError extends Error {
  constructor(message = "Header length mismatch") {
    super(message)
    this.name = "HeaderLengthError"
  }
}

/**
 * Slot header structure (plaintext, inside AEAD).
 */
export interface SlotHeader {
  readonly magic: Uint8Array // 4 bytes
  readonly version: number
  readonly schemeId: number
  readonly allocated: number // 1 byte: 1 = allocated, 0 = free
  readonly salt: Uint8Array // 16 bytes
  readonly nonce: Uint8Array // 12 bytes (XChaCha20 24-byte nonce in payload)
  readonly payloadLen: number
  readonly writtenAtMs: number
  readonly slotNonce: Uint8Array // 16 bytes
}

/**
 * Encode a SlotHeader into exactly HEADER_SIZE bytes using DataView
 * for all multi-byte integers (little-endian).
 */
export const buildHeader = (header: SlotHeader): Uint8Array => {
  const buf = new Uint8Array(HEADER_SIZE)
  const view = new DataView(buf.buffer)
  buf.set(header.magic, 0)
  buf[4] = header.version & 0xFF
  buf[5] = header.schemeId & 0xFF
  buf[6] = header.allocated & 0xFF
  buf[7] = 0
  buf.set(header.salt, 8)
  buf.set(header.nonce, 24)
  view.setUint32(36, header.payloadLen, true)
  // Write uint64 as two uint32 (low, high)
  view.setUint32(40, header.writtenAtMs & 0xFFFFFFFF, true)
  view.setUint32(44, Math.floor(header.writtenAtMs / 0x100000000), true)
  buf.set(header.slotNonce, 48)
  return buf
}

/**
 * Decode HEADER_SIZE bytes into a SlotHeader. Throws VersionMismatchError
 * if version field is not 0x01. Does NOT validate magic here.
 */
export const parseHeader = (bytes: Uint8Array): SlotHeader => {
  if (bytes.length !== HEADER_SIZE) throw new HeaderLengthError()
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const magic = bytes.slice(0, 4)
  const version = bytes[4]
  if (version !== VERSION) throw new VersionMismatchError()
  const schemeId = Number(bytes[5])
  const allocated = Number(bytes[6])
  const salt = bytes.slice(8, 24)
  const nonce = bytes.slice(24, 36)
  const payloadLen = view.getUint32(36, true)
  const writtenAtMs =
    view.getUint32(40, true) + 0x100000000 * view.getUint32(44, true)
  const slotNonce = bytes.slice(48, 64)
  return {
    magic,
    version,
    schemeId,
    allocated,
    salt,
    nonce,
    payloadLen,
    writtenAtMs,
    slotNonce,
  }
}
