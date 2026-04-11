import { HEADER_SIZE } from "./constants.ts"
import { ContainerTooSmallError } from "../errors.ts"

/**
 * Container layout geometry.
 */
export interface ContainerLayout {
  readonly totalSize: number
  readonly maxSlots: number
  readonly slotSize: number
  readonly defaultScheme: number
}

/**
 * Compute and validate container geometry. Throws ContainerTooSmallError
 * if totalSize < 1 MiB or if slotSize cannot fit HEADER_SIZE + 1 byte.
 */
export const computeLayout = (options: {
  totalSize?: number
  maxSlots?: number
  defaultScheme?: number
}): ContainerLayout => {
  const totalSize = options.totalSize ?? 67108864 // 64 MiB
  const maxSlots = options.maxSlots ?? 8
  const defaultScheme = options.defaultScheme ?? 0x01
  if (totalSize < 1048576) throw new ContainerTooSmallError()
  if (maxSlots < 1 || maxSlots > 32) throw new ContainerTooSmallError()
  let slotSize = Math.floor(totalSize / maxSlots)
  slotSize = slotSize - (slotSize % 64)
  if (slotSize < HEADER_SIZE + 1) throw new ContainerTooSmallError()
  return { totalSize, maxSlots, slotSize, defaultScheme }
}

/**
 * Return the byte offset of slot i within the container file.
 */
export const slotOffset = (layout: ContainerLayout, i: number): number => {
  return i * layout.slotSize
}
