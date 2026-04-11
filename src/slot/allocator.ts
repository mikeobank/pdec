import type { ContainerLayout } from "../core/layout.ts"
import { ContainerFullError } from "../errors.ts"
//

/**
 * Return the index of the first slot that appears empty (tryDecryptSlot
 * returns undefined for all passphrases). Throws ContainerFullError
 * if all slots are occupied. Pure function — caller provides slot reader.
 */
export const findFreeSlot = async (
  readSlot: (i: number) => Promise<Uint8Array>,
  layout: ContainerLayout
): Promise<number> => {
  const { parseHeader } = await import("../core/header.ts")
  const { HEADER_SIZE } = await import("../core/constants.ts")
  for (let i = 0; i < layout.maxSlots; ++i) {
    const slotBytes = await readSlot(i)
    let header
    try {
      header = parseHeader(slotBytes.subarray(0, HEADER_SIZE))
    } catch {
      // Any parse error (including version mismatch) means slot is free
      return i
    }
    if (header.allocated === 0) return i
  }
  throw new ContainerFullError()
}

/**
 * Build AEAD additional data for a slot (delegates to buildAAD).
 */
export { buildAAD as buildSlotAAD } from "../core/constants.ts"
