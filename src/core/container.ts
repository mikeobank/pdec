import type { IRandomAccessHandle } from "../io/types.ts"
import { FileHandle } from "../io/file-handle.ts"
import { computeLayout, slotOffset } from "./layout.ts"
//
import { randomBytes, jitter } from "../crypto/random.ts"
import { scanSlots } from "../slot/scanner.ts"
import { findFreeSlot } from "../slot/allocator.ts"
import { validatePassphrase } from "../passphrase/validator.ts"
//
import { InvalidPassphraseError } from "../errors.ts"

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
      ...(options.scheme !== undefined ? { defaultScheme: options.scheme } : {})
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
    const buf = randomBytes(layout.totalSize)
    await file.seek(0, Deno.SeekMode.Start)
    let written = 0
    while (written < buf.length) {
      const n = await file.write(buf.subarray(written))
      if (n === null || n === undefined) throw new Error("Unexpected EOF during write")
      written += n
    }
    await file.sync()
    const handle = new FileHandle(file, layout.totalSize)
    return new PDECContainer(handle, layout)
  }

  /**
   * Open an existing container file. Does not validate any plaintext.
   * Infers layout from file size using computeLayout defaults.
   */
  static async open(path: string): Promise<PDECContainer> {
    const file = await Deno.open(path, { read: true, write: true })
    const stat = await file.stat()
    const layout = computeLayout({ totalSize: stat.size })
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
    const { shuffleIndices } = await import("../crypto/random.ts")
    const order = shuffleIndices(this._layout.maxSlots)
    const result = await scanSlots(
      (i) => this._handle.read(slotOffset(this._layout, i), this._layout.slotSize),
      order,
      passphrase,
      this._layout
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
        passphrase,
        this._layout
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
    if (typeof schemeId !== "number" || Number.isNaN(schemeId)) throw new Error("schemeId must be a number")
    // Force mode to 'unicode' for XChaCha20+Argon2id to match read path
    if (schemeId === 0x02) mode = "unicode"
    const { buildSlot } = await import("./build_slot.ts")
    const slotBuf = await buildSlot({
      passphrase,
      data,
      slotIndex,
      mode,
      schemeId,
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
    const { shuffleIndices } = await import("../crypto/random.ts")
    const order = shuffleIndices(this._layout.maxSlots)
    const result = await scanSlots(
      (i) => this._handle.read(slotOffset(this._layout, i), this._layout.slotSize),
      order,
      passphrase,
      this._layout
    )
    if (!result) return false
    const slotBuf = randomBytes(this._layout.slotSize)
    await this._handle.write(slotOffset(this._layout, result.slotIndex), slotBuf)
    await this._handle.sync()
    return true
  }

  get layout(): ReturnType<typeof computeLayout> {
    return this._layout
  }

  async close(): Promise<void> {
    await this._handle.close()
  }
}
