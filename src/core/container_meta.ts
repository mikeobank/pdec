import type { ContainerLayout } from "./layout.ts"
import type { IRandomAccessHandle } from "../io/types.ts"

const CONTAINER_METADATA_MAGIC = new Uint8Array([0x50, 0x44, 0x45, 0x43]) // P D E C
const CONTAINER_METADATA_VERSION = 0x01
export const CONTAINER_METADATA_SIZE = 64

export interface ContainerMetadata {
  readonly totalSize: number
  readonly maxSlots: number
  readonly defaultScheme: number
  readonly slotSize: number
  readonly dataOffset: number
}

export const writeContainerMetadata = async (handle: IRandomAccessHandle, layout: ContainerLayout): Promise<void> => {
  const bytes = buildContainerMetadata({
    totalSize: layout.totalSize,
    maxSlots: layout.maxSlots,
    defaultScheme: layout.defaultScheme,
    slotSize: layout.slotSize,
    dataOffset: layout.dataOffset
  })
  await handle.write(0, bytes)
}

export const readContainerMetadata = async (handle: IRandomAccessHandle): Promise<ContainerMetadata | undefined> => {
  try {
    const bytes = await handle.read(0, CONTAINER_METADATA_SIZE)
    return parseContainerMetadata(bytes)
  } catch {
    return undefined
  }
}
export const buildContainerMetadata = (meta: ContainerMetadata): Uint8Array => {
  const out = new Uint8Array(CONTAINER_METADATA_SIZE)
  const view = new DataView(out.buffer)
  out.set(CONTAINER_METADATA_MAGIC, 0)
  out[4] = CONTAINER_METADATA_VERSION
  out[5] = meta.maxSlots & 0xFF
  out[6] = meta.defaultScheme & 0xFF
  out[7] = 0
  view.setUint32(8, meta.slotSize, true)
  view.setUint32(12, meta.dataOffset, true)
  view.setUint32(16, meta.totalSize & 0xFFFFFFFF, true)
  view.setUint32(20, Math.floor(meta.totalSize / 0x100000000), true)
  return out
}

export const parseContainerMetadata = (bytes: Uint8Array): ContainerMetadata => {
  if (bytes.length !== CONTAINER_METADATA_SIZE) throw new Error("Invalid container metadata size")
  if (!bytes.subarray(0, 4).every((b, i) => b === CONTAINER_METADATA_MAGIC[i])) {
    throw new Error("Container metadata magic mismatch")
  }
  if (bytes[4] !== CONTAINER_METADATA_VERSION) {
    throw new Error(`Unsupported container metadata version: ${bytes[4]}`)
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const maxSlots = Number(bytes[5])
  const defaultScheme = Number(bytes[6])
  const slotSize = view.getUint32(8, true)
  const dataOffset = view.getUint32(12, true)
  const totalSize = view.getUint32(16, true) + 0x100000000 * view.getUint32(20, true)
  return {
    totalSize,
    maxSlots,
    defaultScheme,
    slotSize,
    dataOffset
  }
}


