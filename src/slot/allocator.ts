import type { ContainerLayout } from "../core/layout.ts"
import { ContainerFullError } from "../errors.ts"
import { MAGIC } from "../core/constants.ts"

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
    const magic = slotBytes.subarray(0, 4)
    let isEmpty = false
    for (let j = 0; j < 4; ++j) {
      if (magic[j] !== MAGIC[j]) {
        isEmpty = true
        break
      }
    }
    if (isEmpty) return i
  }
  throw new ContainerFullError()
}

/**
 * Build AEAD additional data for a slot (delegates to buildAAD).
 */
export { buildAAD as buildSlotAAD } from "../core/constants.ts"
