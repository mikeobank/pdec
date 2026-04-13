import { open } from "node:fs/promises"
import type { FileHandle as NodeFsFileHandle } from "node:fs/promises"
import type { IRandomAccessHandle } from "./types.ts"
import { IOError } from "../errors.ts"

export class NodeFileHandle implements IRandomAccessHandle {
  private fh: NodeFsFileHandle
  readonly size: number

  constructor(fh: NodeFsFileHandle, size: number) {
    this.fh = fh
    this.size = size
  }

  static async open(path: string): Promise<NodeFileHandle> {
    const fh = await open(path, "r+")
    const stat = await fh.stat()
    return new NodeFileHandle(fh, stat.size)
  }

  static async create(path: string, size: number): Promise<NodeFileHandle> {
    const fh = await open(path, "w+")
    await fh.truncate(size)
    return new NodeFileHandle(fh, size)
  }

  async read(offset: number, length: number): Promise<Uint8Array> {
    const buf = new Uint8Array(length)
    let pos = 0
    while (pos < length) {
      const { bytesRead } = await this.fh.read(buf, pos, length - pos, offset + pos)
      if (bytesRead === 0) throw new IOError("Unexpected EOF")
      pos += bytesRead
    }
    return buf
  }

  async write(offset: number, data: Uint8Array): Promise<void> {
    let pos = 0
    while (pos < data.length) {
      const { bytesWritten } = await this.fh.write(data, pos, data.length - pos, offset + pos)
      if (bytesWritten === 0) throw new IOError("Write failed")
      pos += bytesWritten
    }
  }

  async sync(): Promise<void> {
    await this.fh.datasync()
  }

  async close(): Promise<void> {
    await this.fh.close()
  }
}
