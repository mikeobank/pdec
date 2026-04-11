/**
 * PDEC container constants and AAD builder.
 */

export const MAGIC = new Uint8Array([0xDE, 0xC0, 0x1A, 0x57])
export const VERSION = 0x01
export const HEADER_SIZE = 65

/**
 * Build the 6-byte AEAD additional data that binds ciphertext to its
 * physical slot position, preventing block-relocation attacks.
 *
 * @param slotIndex - The index of the slot within the container.
 * @param schemeId - The cryptographic scheme ID.
 * @returns 6-byte Uint8Array for AEAD additional data.
 */
export const buildAAD = (slotIndex: number, schemeId: number): Uint8Array => {
  const aad = new Uint8Array(6)
  aad.set(MAGIC, 0)
  aad[4] = slotIndex & 0xFF
  aad[5] = schemeId & 0xFF
  return aad
}
