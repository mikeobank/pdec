import type { ContainerLayout } from "./layout.ts"

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

const writeAll = async (file: Deno.FsFile, data: Uint8Array): Promise<void> => {
  let pos = 0
  while (pos < data.length) {
    const n = await file.write(data.subarray(pos))
    if (n === null || n === undefined) throw new Error("Failed to write container metadata")
    pos += n
  }
}

const readAll = async (file: Deno.FsFile, len: number): Promise<Uint8Array | undefined> => {
  const buf = new Uint8Array(len)
  let pos = 0
  while (pos < len) {
    const n = await file.read(buf.subarray(pos))
    if (n === null) return undefined
    pos += n
  }
  return buf
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

export const writeContainerMetadata = async (file: Deno.FsFile, layout: ContainerLayout): Promise<void> => {
  const bytes = buildContainerMetadata({
    totalSize: layout.totalSize,
    maxSlots: layout.maxSlots,
    defaultScheme: layout.defaultScheme,
    slotSize: layout.slotSize,
    dataOffset: layout.dataOffset
  })
  await file.seek(0, Deno.SeekMode.Start)
  await writeAll(file, bytes)
}

export const readContainerMetadata = async (file: Deno.FsFile): Promise<ContainerMetadata | undefined> => {
  await file.seek(0, Deno.SeekMode.Start)
  const bytes = await readAll(file, CONTAINER_METADATA_SIZE)
  if (bytes === undefined) return undefined
  try {
    return parseContainerMetadata(bytes)
  } catch {
    return undefined
  }
}
