import { assert, assertEquals, assertRejects } from "@std/assert"
import { PDECContainer } from "../src/core/container.ts"
import { FileHandle } from "../src/io/file-handle.ts"
import { randomBytes } from "../src/crypto/random.ts"
import { MIN_FILE_SIZE } from "../src/core/constants.ts"

const testDir = "./test_containers"

const ensureTestDir = async (): Promise<void> => {
  try {
    await Deno.stat(testDir)
  } catch {
    await Deno.mkdir(testDir)
  }
}

Deno.test("PDECContainer.create writes a valid file", async () => {
  await ensureTestDir()
  const path = `${ testDir }/test1.pdec`
  try {
    const handle = await FileHandle.create(path, MIN_FILE_SIZE, true)
    const c = await PDECContainer.create(handle)
    await c.write("testpass!!", randomBytes(32))
    await c.close()
    const stat = await Deno.stat(path)
    assertEquals(stat.size, MIN_FILE_SIZE)
  } finally {
    await Deno.remove(path).catch(() => {})
  }
})

Deno.test("PDECContainer.create with custom totalSize", async () => {
  await ensureTestDir()
  const path = `${ testDir }/test2.pdec`
  const totalSize = 8388608
  try {
    const handle = await FileHandle.create(path, totalSize, true)
    const c = await PDECContainer.create(handle)
    await c.write("testpass!!", randomBytes(32))
    await c.close()
    const stat = await Deno.stat(path)
    assertEquals(stat.size, totalSize)
  } finally {
    await Deno.remove(path).catch(() => {})
  }
})

Deno.test("PDECContainer.open reads an existing file", async () => {
  await ensureTestDir()
  const path = `${ testDir }/test3.pdec`
  try {
    const handle1 = await FileHandle.create(path, MIN_FILE_SIZE, true)
    const data = randomBytes(32)
    const c1 = await PDECContainer.create(handle1)
    await c1.write("testpass!!", data)
    await c1.close()

    const handle2 = await FileHandle.open(path)
    const c2 = PDECContainer.open(handle2)
    const slot = await c2.read("testpass!!")
    assert(slot)
    assertEquals(slot.data, data)
    await c2.close()
  } finally {
    await Deno.remove(path).catch(() => {})
  }
})

Deno.test("FileHandle.create rejects if file exists and overwrite=false", async () => {
  await ensureTestDir()
  const path = `${ testDir }/test4.pdec`
  try {
    const handle = await FileHandle.create(path, MIN_FILE_SIZE, true)
    const c = await PDECContainer.create(handle)
    await c.close()
    await assertRejects(() => FileHandle.create(path, MIN_FILE_SIZE, false), Error)
  } finally {
    await Deno.remove(path).catch(() => {})
  }
})

Deno.test("Multiple passphrases in same session", async () => {
  await ensureTestDir()
  const path = `${ testDir }/test5.pdec`
  try {
    const handle = await FileHandle.create(path, MIN_FILE_SIZE, true)
    const c = await PDECContainer.create(handle)
    const data1 = randomBytes(32)
    const data2 = randomBytes(32)
    await c.write("password1!!", data1)
    await c.write("password2!!", data2)
    const slot1 = await c.read("password1!!")
    const slot2 = await c.read("password2!!")
    assert(slot1)
    assert(slot2)
    assertEquals(slot1.data, data1)
    assertEquals(slot2.data, data2)
    await c.close()
  } finally {
    await Deno.remove(path).catch(() => {})
  }
})

Deno.test("Wipe persists across container close/reopen", async () => {
  await ensureTestDir()
  const path = `${ testDir }/test6.pdec`
  try {
    const handle1 = await FileHandle.create(path, MIN_FILE_SIZE, true)
    const c1 = await PDECContainer.create(handle1)
    await c1.write("testpass!!", randomBytes(32))
    await c1.wipe("testpass!!")
    await c1.close()

    const handle2 = await FileHandle.open(path)
    const c2 = PDECContainer.open(handle2)
    const slot = await c2.read("testpass!!")
    assertEquals(slot, undefined)
    await c2.close()
  } finally {
    await Deno.remove(path).catch(() => {})
  }
})
