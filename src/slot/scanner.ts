import type { SlotHeader } from "../core/header.ts"
import type { ContainerLayout } from "../core/layout.ts"
import { tryDecryptSlot as _tryDecryptSlot } from "./scanner_impl.ts"

export interface ScanResult {
  readonly found: boolean
  readonly slotIndex: number
  readonly header: SlotHeader
  readonly payload: Uint8Array
}

/**
 * Try to decrypt one slot's raw bytes with the given passphrase.
 * Returns undefined on any AEAD failure. Never throws on auth failure.
 * Pure function — receives raw bytes, returns a result or undefined.
 */
export const tryDecryptSlot = (
  slotBytes: Uint8Array,
  slotIndex: number,
  passphrase: string,
  layout: ContainerLayout
// ...existing code...
): Promise<ScanResult | undefined> => {
  // Implementation in scanner_impl.ts for clarity
  return _tryDecryptSlot(slotBytes, slotIndex, passphrase, layout)
}

/**
 * Scan all slots in the given order, always attempting every slot.
 * Returns the first successful ScanResult, or undefined if none matched.
 * The order array must be pre-shuffled by the caller (container.ts).
 */
export const scanSlots = async (
  readSlot: (i: number) => Promise<Uint8Array>,
  order: number[],
  passphrase: string,
  layout: ContainerLayout
): Promise<ScanResult | undefined> => {
  for (const i of order) {
    const slotBytes = await readSlot(i)
    const candidate = await tryDecryptSlot(slotBytes, i, passphrase, layout)
    if (candidate !== undefined) return candidate
  }
  return undefined
}
