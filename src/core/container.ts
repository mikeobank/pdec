import type { IRandomAccessHandle } from "../io/types.ts"
import { FileHandle } from "../io/file-handle.ts"
import { computeLayout, slotOffset } from "./layout.ts"
import { CONTAINER_METADATA_SIZE, readContainerMetadata, writeContainerMetadata } from "./container_meta.ts"
//
import { randomBytes, jitter, shuffleIndices } from "../crypto/random.ts"
import { scanSlots } from "../slot/scanner.ts"
import { findFreeSlot } from "../slot/allocator.ts"
import { buildSlot } from "./build_slot.ts"
import { validatePassphrase } from "../passphrase/validator.ts"
import { resolveScheme } from "../crypto/registry.ts"
//
import { InvalidLayoutError, InvalidPassphraseError } from "../errors.ts"
import { ALLOCATED_BYTE_OFFSET } from "./constants.ts"

export interface PDECCreateOptions {
  path: string
  totalSize?: number
  maxSlots?: number
  scheme?: number
  overwrite?: boolean
}

export interface WriteOptions {
  scheme?: number
  forceNewSlot?: boolean
}

export interface SlotData {
  readonly data: Uint8Array
  readonly schemeId: number
  readonly writtenAt: Date
  readonly slotIndex: number
}

/**
 * PDECContainer is the only class in the library. Owns one IRandomAccessHandle and one ContainerLayout.
 * All cryptographic logic is delegated to the functional core.
 */
export class PDECContainer {
  private _handle: IRandomAccessHandle
  private _layout: ReturnType<typeof computeLayout>

  private constructor(handle: IRandomAccessHandle, layout: ReturnType<typeof computeLayout>) {
    this._handle = handle
    this._layout = layout
  }

  /**
   * Create a new container file. Fill entirely with randomBytes() before returning.
   * Throw if file exists and overwrite is false.
   */
  static async create(options: PDECCreateOptions): Promise<PDECContainer> {
    const layout = computeLayout({
      ...(options.totalSize !== undefined ? { totalSize: options.totalSize } : {}),
      ...(options.maxSlots !== undefined ? { maxSlots: options.maxSlots } : {}),
      ...(options.scheme !== undefined ? { defaultScheme: options.scheme } : {}),
      metadataBytes: CONTAINER_METADATA_SIZE
    })
    let file: Deno.FsFile
    try {
      if (!options.overwrite) {
        file = await Deno.open(options.path, { createNew: true, write: true, read: true })
      } else {
        file = await Deno.open(options.path, { create: true, write: true, read: true, truncate: true })
      }
    } catch (e) {
      const msg = typeof e === "object" && e && "message" in e ? (e as { message?: string }).message : undefined
      throw new Error("Failed to open file: " + (msg ?? "unknown error"))
    }
    await file.seek(0, Deno.SeekMode.Start)
    let written = 0
    const chunkSize = 1048576 // 1 MiB chunks
    while (written < layout.totalSize) {
      const remaining = layout.totalSize - written
      const currentChunkSize = Math.min(chunkSize, remaining)
      const chunk = randomBytes(currentChunkSize)
      let pos = 0
      while (pos < chunk.length) {
        const n = await file.write(chunk.subarray(pos))
        if (n === null || n === undefined) throw new Error("Unexpected EOF during write")
        pos += n
      }
      written += currentChunkSize
    }
    await writeContainerMetadata(file, layout)
    for (let i = 0; i < layout.maxSlots; ++i) {
      await file.seek(slotOffset(layout, i) + ALLOCATED_BYTE_OFFSET, Deno.SeekMode.Start)
      const n = await file.write(new Uint8Array([0]))
      if (n !== 1) throw new Error("Failed to initialize free-slot marker")
    }
    await file.sync()
    const handle = new FileHandle(file, layout.totalSize)
    return new PDECContainer(handle, layout)
  }

  /**
   * Open an existing container file.
   * Reads persisted container metadata when present.
   * Falls back to legacy size-based inference for old containers.
   */
  static async open(path: string): Promise<PDECContainer> {
    const file = await Deno.open(path, { read: true, write: true })
    const stat = await file.stat()
    const metadata = await readContainerMetadata(file)
    let layout
    if (metadata !== undefined) {
      layout = computeLayout({
        totalSize: stat.size,
        maxSlots: metadata.maxSlots,
        defaultScheme: metadata.defaultScheme,
        metadataBytes: metadata.dataOffset
      })
      if (metadata.totalSize !== stat.size || metadata.slotSize !== layout.slotSize || metadata.dataOffset !== layout.dataOffset) {
        throw new InvalidLayoutError("Container metadata does not match file geometry")
      }
    } else {
      layout = computeLayout({ totalSize: stat.size })
    }
    const handle = new FileHandle(file, stat.size)
    return new PDECContainer(handle, layout)
  }

  /**
   * Internal factory used by tests — accepts any IRandomAccessHandle.
   * Not exported from mod.ts.
   */
  static _fromHandle(handle: IRandomAccessHandle, layout: ReturnType<typeof computeLayout>): PDECContainer {
    return new PDECContainer(handle, layout)
  }

  /**
   * Shuffle slot indices, scan all slots, apply jitter.
   * Returns SlotData on success, undefined if no slot matched.
   */
  async read(passphrase: string): Promise<SlotData | undefined> {
    const order = shuffleIndices(this._layout.maxSlots)
    const result = await scanSlots(
      (i) => this._handle.read(slotOffset(this._layout, i), this._layout.slotSize),
      order,
      passphrase
    )
    await jitter(50, 200)
    if (!result) return undefined
    return {
      data: result.payload,
      schemeId: result.header.schemeId,
      writtenAt: new Date(result.header.writtenAtMs),
      slotIndex: result.slotIndex
    }
  }

  /**
   * Validate passphrase, find or allocate slot, encrypt, write, sync.
   */
  async write(passphrase: string, data: Uint8Array, options?: WriteOptions): Promise<void> {
    const validation = validatePassphrase(passphrase)
    if (!validation.valid) throw new InvalidPassphraseError()
    let mode = validation.mode
    let slotIndex: number | undefined = undefined
    if (!options?.forceNewSlot) {
      // Try to find existing slot for this passphrase
      const order = Array.from({ length: this._layout.maxSlots }, (_, i) => i)
      const result = await scanSlots(
        (i) => this._handle.read(slotOffset(this._layout, i), this._layout.slotSize),
        order,
        passphrase
      )
      if (result) slotIndex = result.slotIndex
    }
    if (slotIndex === undefined) {
      slotIndex = await findFreeSlot(
        (i) => this._handle.read(slotOffset(this._layout, i), this._layout.slotSize),
        this._layout
      )
    }
    const schemeId: number = options?.scheme !== undefined ? options.scheme! : this._layout.defaultScheme
    if (typeof schemeId !== "number" || !Number.isInteger(schemeId) || schemeId < 0 || schemeId > 255) {
      throw new Error("schemeId must be an integer in range 0..255")
    }
    const scheme = resolveScheme(schemeId)
    if (scheme.forceMode !== undefined) mode = scheme.forceMode
    const slotBuf = await buildSlot({
      passphrase,
      data,
      slotIndex,
      mode,
      scheme,
      slotSize: this._layout.slotSize
    })
    await this._handle.write(slotOffset(this._layout, slotIndex), slotBuf)
    await this._handle.sync()
  }

  /**
   * Find slot, overwrite with randomBytes, sync.
   * Returns false if passphrase had no slot, true if wiped.
   */
  async wipe(passphrase: string): Promise<boolean> {
    const order = shuffleIndices(this._layout.maxSlots)
    const result = await scanSlots(
      (i) => this._handle.read(slotOffset(this._layout, i), this._layout.slotSize),
      order,
      passphrase
    )
    if (!result) return false
    const slotBuf = randomBytes(this._layout.slotSize)
    slotBuf[ALLOCATED_BYTE_OFFSET] = 0
    await this._handle.write(slotOffset(this._layout, result.slotIndex), slotBuf)
    await this._handle.sync()
    return true
  }

  _readSlotBytes(i: number): Promise<Uint8Array> {
    return this._handle.read(slotOffset(this._layout, i), this._layout.slotSize)
  }

  get layout(): ReturnType<typeof computeLayout> {
    return this._layout
  }

  async close(): Promise<void> {
    await this._handle.close()
  }
}
