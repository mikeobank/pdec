export const DOMAIN_MAGIC = new Uint8Array([0xDE, 0xC0, 0x1A, 0x57])
export const VERSION = 0x02
export const BLOCK_ALIGN = 64
export const MAX_CIPHERTEXT_SIZE = 65536
export const MAX_COLLISION_RETRIES = 8
export const MIN_FILE_SIZE = 4194304

export const DOMAIN_SALT = new Uint8Array([
  0x6b, 0x25, 0xc6, 0xfb, 0x13, 0xa5, 0xc3, 0x5b,
  0xc8, 0x92, 0xdd, 0x4b, 0x8f, 0xdf, 0xf6, 0x22,
  0x3d, 0x55, 0x7b, 0x94, 0x51, 0x8a, 0x05, 0xb0,
  0xc8, 0xa9, 0x24, 0x8e, 0xe5, 0x26, 0x5d, 0x63
])

export const NONCE_SIZE_AES = 12
export const NONCE_SIZE_XCHACHA = 24
export const TAG_SIZE = 16
export const PLAINTEXT_ENVELOPE_SIZE = MAX_CIPHERTEXT_SIZE - NONCE_SIZE_AES - TAG_SIZE

export const buildAAD = (address: number, schemeId: number): Uint8Array => {
  const aad = new Uint8Array(9)
  const view = new DataView(aad.buffer)
  aad.set(DOMAIN_MAGIC, 0)
  view.setUint32(4, address, true)
  aad[8] = schemeId & 0xFF
  return aad
}
