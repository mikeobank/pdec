import type { IRandomAccessHandle } from "./types.ts"

/**
 * BufferHandle implements IRandomAccessHandle for in-memory Uint8Array.
 * Used exclusively in tests.
 */
export class BufferHandle implements IRandomAccessHandle {
  private buf: Uint8Array
  readonly size: number

  constructor(buf: Uint8Array) {
    this.buf = buf
    this.size = buf.length
  }

  read(offset: number, length: number): Promise<Uint8Array> {
    if (offset + length > this.size) throw new Error("Out of bounds read")
    return Promise.resolve(this.buf.slice(offset, offset + length))
  }

  write(offset: number, data: Uint8Array): Promise<void> {
    if (offset + data.length > this.size) throw new Error("Out of bounds write")
    this.buf.set(data, offset)
    return Promise.resolve()
  }

  sync(): Promise<void> {
    // no-op
    return Promise.resolve()
  }

  close(): Promise<void> {
    // no-op
    return Promise.resolve()
  }
}
