import type { IRandomAccessHandle } from "./types.ts"
import { IOError } from "../errors.ts"

export class FileHandle implements IRandomAccessHandle {
  private file: Deno.FsFile
  readonly size: number

  constructor(file: Deno.FsFile, size: number) {
    this.file = file
    this.size = size
  }

  static async open(path: string): Promise<FileHandle> {
    const file = await Deno.open(path, { read: true, write: true })
    const stat = await file.stat()
    return new FileHandle(file, stat.size)
  }

  static async create(path: string, size: number, overwrite = false): Promise<FileHandle> {
    const options = overwrite
      ? { create: true, write: true, read: true, truncate: true }
      : { createNew: true, write: true, read: true }
    const file = await Deno.open(path, options)
    return new FileHandle(file, size)
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
