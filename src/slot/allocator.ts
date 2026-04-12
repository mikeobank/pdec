import type { ContainerLayout } from "../core/layout.ts"
import { ContainerFullError } from "../errors.ts"
import { parseHeader } from "../core/header.ts"
import { ALLOCATED_BYTE_OFFSET, HEADER_SIZE, MAGIC } from "../core/constants.ts"

/**
 * Return the index of the first slot that appears empty (tryDecryptSlot
 * returns undefined for all passphrases). Throws ContainerFullError
 * if all slots are occupied. Pure function — caller provides slot reader.
 */
export const findFreeSlot = async (
  readSlot: (i: number) => Promise<Uint8Array>,
  layout: ContainerLayout
): Promise<number> => {
  for (let i = 0; i < layout.maxSlots; ++i) {
    const slotBytes = await readSlot(i)
    const allocatedFlag = slotBytes[ALLOCATED_BYTE_OFFSET]
    if (allocatedFlag !== 0) continue
    const magicBytes = slotBytes.subarray(0, 4)
    const isMagicValid = magicBytes.every((b, idx) => b === MAGIC[idx])
    if (!isMagicValid) {
      return i
    }
    let header
    try {
      header = parseHeader(slotBytes.subarray(0, HEADER_SIZE))
    } catch {
      continue
    }
    if (header.allocated === 0) return i
  }
  throw new ContainerFullError()
}

/**
 * Build AEAD additional data for a slot (delegates to buildAAD).
 */
export { buildAAD as buildSlotAAD } from "../core/constants.ts"
