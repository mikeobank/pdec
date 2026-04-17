import { BLOCK_ALIGN, MAX_CIPHERTEXT_SIZE, MAX_COLLISION_RETRIES } from "./constants.ts"
import { deriveAddressMaterial } from "../crypto/kdf.ts"
import { detectPassphraseMode } from "../passphrase/validator.ts"
import { CollisionError } from "../errors.ts"

export interface DerivedAddress {
  readonly encryptionKey: Uint8Array
  readonly address: number
  readonly baseAddress: number
  readonly retryIndex: number
}

const alignedRange = (totalSize: number): number =>
  Math.floor((totalSize - MAX_CIPHERTEXT_SIZE) / BLOCK_ALIGN) * BLOCK_ALIGN

const baseAddressFromMaterial = (material: Uint8Array, totalSize: number): number => {
  const view = new DataView(material.buffer, material.byteOffset + 32, 4)
  const raw = view.getUint32(0, true)
  const range = alignedRange(totalSize)
  return Math.floor((raw % range) / BLOCK_ALIGN) * BLOCK_ALIGN
}

export const computeRetryAddress = (baseAddress: number, retryIndex: number, totalSize: number): number => {
  if (retryIndex === 0) return baseAddress
  const range = alignedRange(totalSize)
  return Math.floor(((baseAddress + retryIndex * MAX_CIPHERTEXT_SIZE) % range) / BLOCK_ALIGN) * BLOCK_ALIGN
}

export const deriveAddress = (passphrase: string, totalSize: number, retryIndex = 0): DerivedAddress => {
  const mode = detectPassphraseMode(passphrase)
  const material = deriveAddressMaterial(passphrase, mode)
  try {
    const encryptionKey = material.slice(0, 32)
    const base = baseAddressFromMaterial(material, totalSize)
    const address = computeRetryAddress(base, retryIndex, totalSize)
    return { encryptionKey, address, baseAddress: base, retryIndex }
  } finally {
    material.fill(0)
  }
}

export const rangesOverlap = (addrA: number, addrB: number): boolean =>
  Math.abs(addrA - addrB) < MAX_CIPHERTEXT_SIZE

export const resolveCollision = (
  passphrase: string,
  totalSize: number,
  existingAddresses: number[]
): DerivedAddress => {
  const mode = detectPassphraseMode(passphrase)
  const material = deriveAddressMaterial(passphrase, mode)
  try {
    const encryptionKey = material.slice(0, 32)
    const base = baseAddressFromMaterial(material, totalSize)

    for (let k = 0; k <= MAX_COLLISION_RETRIES; k++) {
      const candidate = computeRetryAddress(base, k, totalSize)
      const collides = existingAddresses.some(existing => rangesOverlap(candidate, existing))
      if (!collides) {
        return { encryptionKey, address: candidate, baseAddress: base, retryIndex: k }
      }
    }
    encryptionKey.fill(0)
    throw new CollisionError("Could not find non-overlapping address after MAX_COLLISION_RETRIES")
  } finally {
    material.fill(0)
  }
}

