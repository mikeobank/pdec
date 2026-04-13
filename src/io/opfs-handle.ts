import type { IRandomAccessHandle } from "./types.ts"
import { IOError } from "../errors.ts"

// Local type declarations for OPFS APIs not covered by all lib targets.
// FileSystemSyncAccessHandle is only available in dedicated Workers.
// See: https://developer.mozilla.org/en-US/docs/Web/API/FileSystemSyncAccessHandle

interface FileSystemSyncAccessHandle {
  read(buffer: ArrayBufferView, options?: { at?: number }): number
  write(buffer: ArrayBufferView, options?: { at?: number }): number
  getSize(): number
  truncate(newSize: number): void
  flush(): void
  close(): void
}

interface FileSystemFileHandle {
  createSyncAccessHandle(): Promise<FileSystemSyncAccessHandle>
}

interface FileSystemDirectoryHandle {
  getFileHandle(name: string, options?: { create?: boolean }): Promise<FileSystemFileHandle>
}

interface StorageManager {
  getDirectory(): Promise<FileSystemDirectoryHandle>
}

declare const navigator: { storage: StorageManager }

export class OPFSHandle implements IRandomAccessHandle {
  private handle: FileSystemSyncAccessHandle
  readonly size: number

  constructor(handle: FileSystemSyncAccessHandle, size: number) {
    this.handle = handle
    this.size = size
  }

  static async open(name: string): Promise<OPFSHandle> {
    const root = await navigator.storage.getDirectory()
    const fileHandle = await root.getFileHandle(name)
    const syncHandle = await fileHandle.createSyncAccessHandle()
    return new OPFSHandle(syncHandle, syncHandle.getSize())
  }

  static async create(name: string, size: number): Promise<OPFSHandle> {
    const root = await navigator.storage.getDirectory()
    const fileHandle = await root.getFileHandle(name, { create: true })
    const syncHandle = await fileHandle.createSyncAccessHandle()
    syncHandle.truncate(size)
    return new OPFSHandle(syncHandle, size)
  }

  read(offset: number, length: number): Promise<Uint8Array> {
    const buf = new Uint8Array(length)
    const bytesRead = this.handle.read(buf, { at: offset })
    if (bytesRead < length) return Promise.reject(new IOError("Unexpected EOF"))
    return Promise.resolve(buf)
  }

  write(offset: number, data: Uint8Array): Promise<void> {
    const bytesWritten = this.handle.write(data, { at: offset })
    if (bytesWritten < data.length) return Promise.reject(new IOError("Write failed"))
    return Promise.resolve()
  }

  sync(): Promise<void> {
    this.handle.flush()
    return Promise.resolve()
  }

  close(): Promise<void> {
    this.handle.close()
    return Promise.resolve()
  }
}
