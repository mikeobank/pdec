import type { IRandomAccessHandle } from "./types.ts"
import { IOError } from "../errors.ts"

/**
 * FileHandle implements IRandomAccessHandle for Deno.FsFile.
 */
export class FileHandle implements IRandomAccessHandle {
  private file: Deno.FsFile
  readonly size: number

  constructor(file: Deno.FsFile, size: number) {
    this.file = file
    this.size = size
  }

  async read(offset: number, length: number): Promise<Uint8Array> {
    const buf = new Uint8Array(length)
    await this.file.seek(offset, Deno.SeekMode.Start)
    let pos = 0
    while (pos < length) {
      const n = await this.file.read(buf.subarray(pos))
      if (n === null || n === undefined) throw new IOError("Unexpected EOF")
      pos += n
    }
    return buf
  }

  async write(offset: number, data: Uint8Array): Promise<void> {
    await this.file.seek(offset, Deno.SeekMode.Start)
    let pos = 0
    while (pos < data.length) {
      const n = await this.file.write(data.subarray(pos))
      if (n === null || n === undefined) throw new IOError("Write failed")
      pos += n
    }
  }

  async sync(): Promise<void> {
    await this.file.sync()
  }

  close(): Promise<void> {
    this.file.close()
    return Promise.resolve()
  }
}
