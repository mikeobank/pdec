import { assertEquals, assertRejects } from "@std/assert"
import { FileHandle } from "../src/io/file-handle.ts"
import { NodeFileHandle } from "../src/io/node-file-handle.ts"
import { OPFSHandle } from "../src/io/opfs-handle.ts"
import { IOError } from "../src/errors.ts"

// ---------------------------------------------------------------------------
// FileHandle tests (Deno-native)
// ---------------------------------------------------------------------------

const testDir = "./test_containers"

const ensureTestDir = async () => {
  try {
    await Deno.stat(testDir)
  } catch {
    await Deno.mkdir(testDir)
  }
}

Deno.test("FileHandle write and read round-trip", async () => {
  await ensureTestDir()
  const path = `${ testDir }/fh_test1.bin`
  try {
    const file = await Deno.open(path, { create: true, write: true, read: true, truncate: true })
    const h = new FileHandle(file, 4096)
    const data = new Uint8Array([1, 2, 3, 4])
    await h.write(0, data)
    await h.sync()
    const result = await h.read(0, 4)
    assertEquals(result, data)
    await h.close()
  } finally {
    await Deno.remove(path).catch(() => {})
  }
})

Deno.test("FileHandle read/write at offset", async () => {
  await ensureTestDir()
  const path = `${ testDir }/fh_test2.bin`
  try {
    const file = await Deno.open(path, { create: true, write: true, read: true, truncate: true })
    const h = new FileHandle(file, 4096)
    const data = new Uint8Array([0xaa, 0xbb, 0xcc])
    await h.write(128, data)
    await h.sync()
    const result = await h.read(128, 3)
    assertEquals(result, data)
    await h.close()
  } finally {
    await Deno.remove(path).catch(() => {})
  }
})

// ---------------------------------------------------------------------------
// NodeFileHandle tests
// ---------------------------------------------------------------------------


Deno.test("NodeFileHandle.create allocates correct size", async () => {
  await ensureTestDir()
  const path = `${ testDir }/node_test1.bin`
  try {
    const h = await NodeFileHandle.create(path, 4096)
    assertEquals(h.size, 4096)
    await h.close()
    const stat = await Deno.stat(path)
    assertEquals(stat.size, 4096)
  } finally {
    await Deno.remove(path).catch(() => {})
  }
})

Deno.test("NodeFileHandle write and read round-trip", async () => {
  await ensureTestDir()
  const path = `${ testDir }/node_test2.bin`
  try {
    const h = await NodeFileHandle.create(path, 4096)
    const data = new Uint8Array([1, 2, 3, 4, 5])
    await h.write(0, data)
    await h.sync()
    await h.close()

    const h2 = await NodeFileHandle.open(path)
    const result = await h2.read(0, 5)
    assertEquals(result, data)
    await h2.close()
  } finally {
    await Deno.remove(path).catch(() => {})
  }
})

Deno.test("NodeFileHandle write and read at offset", async () => {
  await ensureTestDir()
  const path = `${ testDir }/node_test3.bin`
  try {
    const h = await NodeFileHandle.create(path, 4096)
    const data = new Uint8Array([10, 20, 30])
    await h.write(100, data)
    await h.sync()
    await h.close()

    const h2 = await NodeFileHandle.open(path)
    const result = await h2.read(100, 3)
    assertEquals(result, data)
    await h2.close()
  } finally {
    await Deno.remove(path).catch(() => {})
  }
})

Deno.test("NodeFileHandle multiple non-overlapping writes persist independently", async () => {
  await ensureTestDir()
  const path = `${ testDir }/node_test4.bin`
  try {
    const h = await NodeFileHandle.create(path, 4096)
    const a = new Uint8Array([0xaa, 0xbb])
    const b = new Uint8Array([0xcc, 0xdd])
    await h.write(0, a)
    await h.write(200, b)
    await h.sync()
    await h.close()

    const h2 = await NodeFileHandle.open(path)
    assertEquals(await h2.read(0, 2), a)
    assertEquals(await h2.read(200, 2), b)
    await h2.close()
  } finally {
    await Deno.remove(path).catch(() => {})
  }
})

// ---------------------------------------------------------------------------
// OPFSHandle tests (using in-memory mock of FileSystemSyncAccessHandle)
// ---------------------------------------------------------------------------

const makeMockSyncHandle = (size: number) => {
  const buf = new Uint8Array(size)
  let closed = false
  let flushed = false

  const handle = {
    read(buffer: ArrayBufferView, options?: { at?: number }): number {
      const at = options?.at ?? 0
      const dst = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
      const len = Math.min(dst.length, size - at)
      dst.set(buf.subarray(at, at + len))
      return len
    },
    write(buffer: ArrayBufferView, options?: { at?: number }): number {
      const at = options?.at ?? 0
      const src = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
      buf.set(src, at)
      return src.length
    },
    getSize(): number { return size },
    truncate(_newSize: number): void {},
    flush(): void { flushed = true },
    close(): void { closed = true },
    _buf(): Uint8Array { return buf },
    _closed(): boolean { return closed },
    _flushed(): boolean { return flushed }
  }
  return handle
}

Deno.test("OPFSHandle read/write round-trip via mock", async () => {
  const mock = makeMockSyncHandle(4096)
  const h = new OPFSHandle(mock, mock.getSize())
  const data = new Uint8Array([5, 6, 7, 8])
  await h.write(0, data)
  const result = await h.read(0, 4)
  assertEquals(result, data)
})

Deno.test("OPFSHandle write and read at offset via mock", async () => {
  const mock = makeMockSyncHandle(4096)
  const h = new OPFSHandle(mock, mock.getSize())
  const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
  await h.write(256, data)
  const result = await h.read(256, 4)
  assertEquals(result, data)
})

Deno.test("OPFSHandle sync calls flush on mock", async () => {
  const mock = makeMockSyncHandle(4096)
  const h = new OPFSHandle(mock, mock.getSize())
  await h.sync()
  assertEquals(mock._flushed(), true)
})

Deno.test("OPFSHandle close calls close on mock", async () => {
  const mock = makeMockSyncHandle(4096)
  const h = new OPFSHandle(mock, mock.getSize())
  await h.close()
  assertEquals(mock._closed(), true)
})

Deno.test("OPFSHandle read throws IOError on short read", async () => {
  const shortMock = {
    read(_buffer: ArrayBufferView, _options?: { at?: number }): number { return 0 },
    write(_buffer: ArrayBufferView, _options?: { at?: number }): number { return 0 },
    getSize(): number { return 4096 },
    truncate(_newSize: number): void {},
    flush(): void {},
    close(): void {}
  }
  const h = new OPFSHandle(shortMock, 4096)
  await assertRejects(() => h.read(0, 10), IOError, "Unexpected EOF")
})

Deno.test("OPFSHandle write throws IOError on short write", async () => {
  const shortMock = {
    read(_buffer: ArrayBufferView, _options?: { at?: number }): number { return 0 },
    write(_buffer: ArrayBufferView, _options?: { at?: number }): number { return 0 },
    getSize(): number { return 4096 },
    truncate(_newSize: number): void {},
    flush(): void {},
    close(): void {}
  }
  const h = new OPFSHandle(shortMock, 4096)
  await assertRejects(() => h.write(0, new Uint8Array([1, 2, 3])), IOError, "Write failed")
})

// Cleanup
Deno.test({
  name: "cleanup node test files",
  sanitizeResources: false,
  sanitizeOps: false,
  fn: async () => {
    await Deno.remove(testDir, { recursive: true }).catch(() => {})
  }
})
