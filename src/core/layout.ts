import { HEADER_SIZE } from "./constants.ts"
import { ContainerTooSmallError, InvalidLayoutError } from "../errors.ts"

/**
 * Container layout geometry.
 */
export interface ContainerLayout {
  readonly totalSize: number
  readonly maxSlots: number
  readonly slotSize: number
  readonly defaultScheme: number
  readonly dataOffset: number
}

/**
 * Compute and validate container geometry. Throws ContainerTooSmallError
 * if totalSize < 1 MiB or if slotSize cannot fit HEADER_SIZE + 1 byte.
 */
export const computeLayout = (options: {
  totalSize?: number
  maxSlots?: number
  defaultScheme?: number
  metadataBytes?: number
}): ContainerLayout => {
  const totalSize = options.totalSize ?? 67108864 // 64 MiB
  const maxSlots = options.maxSlots ?? 8
  const defaultScheme = options.defaultScheme ?? 0x01
  const metadataBytes = options.metadataBytes ?? 0
  if (totalSize < 1048576) throw new ContainerTooSmallError()
  if (!Number.isInteger(metadataBytes) || metadataBytes < 0) {
    throw new InvalidLayoutError(`metadataBytes must be a non-negative integer, got ${metadataBytes}`)
  }
  if (metadataBytes >= totalSize) {
    throw new InvalidLayoutError(`metadataBytes must be smaller than totalSize, got ${metadataBytes}`)
  }
  if (maxSlots < 1 || maxSlots > 32) throw new InvalidLayoutError(`maxSlots must be in range 1..32, got ${maxSlots}`)
  let slotSize = Math.floor((totalSize - metadataBytes) / maxSlots)
  slotSize = slotSize - (slotSize % 64)
  if (slotSize < HEADER_SIZE + 1) throw new ContainerTooSmallError()
  return { totalSize, maxSlots, slotSize, defaultScheme, dataOffset: metadataBytes }
}

/**
 * Return the byte offset of slot i within the container file.
 */
export const slotOffset = (layout: ContainerLayout, i: number): number => {
  return layout.dataOffset + i * layout.slotSize
}
