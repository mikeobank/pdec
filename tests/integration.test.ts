import { assert, assertEquals, assertRejects } from "@std/assert"
import { PDECContainer } from "../src/core/container.ts"
import { randomBytes } from "../src/crypto/random.ts"
import { ContainerTooSmallError, InvalidLayoutError } from "../src/errors.ts"

const testDir = "./test_containers"

const ensureTestDir = async () => {
  try {
    await Deno.stat(testDir)
  } catch {
    await Deno.mkdir(testDir)
  }
}

Deno.test("PDECContainer.create writes a valid file", async () => {
  await ensureTestDir()
  const path = `${testDir}/test1.pdec`
  try {
    const c = await PDECContainer.create({ path, overwrite: true })
    await c.write("testpass", randomBytes(32))
    await c.close()
    const stat = await Deno.stat(path)
    assertEquals(stat.size, 67108864) // default 64 MiB
  } finally {
    try {
      await Deno.remove(path)
    } catch {
      // ignore
    }
  }
})

Deno.test("PDECContainer.create with custom totalSize", async () => {
  await ensureTestDir()
  const path = `${testDir}/test2.pdec`
  try {
    const c = await PDECContainer.create({ path, totalSize: 10485760, overwrite: true }) // 10 MiB
    await c.write("testpass", randomBytes(32))
    await c.close()
    const stat = await Deno.stat(path)
    assertEquals(stat.size, 10485760)
  } finally {
    try {
      await Deno.remove(path)
    } catch {
      // ignore
    }
  }
})

Deno.test("PDECContainer.open reads an existing file", async () => {
  await ensureTestDir()
  const path = `${testDir}/test3.pdec`
  try {
    const c1 = await PDECContainer.create({ path, totalSize: 10485760, overwrite: true })
    const data = randomBytes(32)
    await c1.write("testpass", data)
    await c1.close()
    const c2 = await PDECContainer.open(path)
    const slot = await c2.read("testpass")
    assert(slot)
    assertEquals(slot.data, data)
    await c2.close()
  } finally {
    try {
      await Deno.remove(path)
    } catch {
      // ignore
    }
  }
})

Deno.test("PDECContainer.create rejects if file exists and overwrite=false", async () => {
  await ensureTestDir()
  const path = `${testDir}/test4.pdec`
  try {
    const c1 = await PDECContainer.create({ path, overwrite: true })
    await c1.close()
    await assertRejects(
      () => PDECContainer.create({ path, overwrite: false }),
      Error
    )
  } finally {
    try {
      await Deno.remove(path)
    } catch {
      // ignore
    }
  }
})

Deno.test("PDECContainer.create rejects totalSize < 1 MiB", async () => {
  await assertRejects(
    () => PDECContainer.create({ path: "/tmp/nope", totalSize: 1024 }),
    ContainerTooSmallError
  )
})

Deno.test("PDECContainer.create rejects invalid maxSlots", async () => {
  await assertRejects(
    () => PDECContainer.create({ path: "/tmp/nope", maxSlots: 33 }),
    InvalidLayoutError
  )
})

Deno.test("Multiple passphrases in same session", async () => {
  await ensureTestDir()
  const path = `${testDir}/test5.pdec`
  try {
    const c = await PDECContainer.create({ path, totalSize: 67108864, maxSlots: 4, overwrite: true })
    const data1 = randomBytes(32)
    const data2 = randomBytes(32)
    await c.write("password1", data1)
    await c.write("password2", data2)
    const slot1 = await c.read("password1")
    const slot2 = await c.read("password2")
    assert(slot1)
    assert(slot2)
    assertEquals(slot1.data, data1)
    assertEquals(slot2.data, data2)
    await c.close()
  } finally {
    try {
      await Deno.remove(path)
    } catch {
      // ignore
    }
  }
})

Deno.test("Wipe persists across container close/reopen", async () => {
  await ensureTestDir()
  const path = `${testDir}/test6.pdec`
  try {
    const c1 = await PDECContainer.create({ path, totalSize: 10485760, overwrite: true })
    await c1.write("testpass", randomBytes(32))
    await c1.wipe("testpass")
    await c1.close()
    const c2 = await PDECContainer.open(path)
    const slot = await c2.read("testpass")
    assertEquals(slot, undefined)
    await c2.close()
  } finally {
    try {
      await Deno.remove(path)
    } catch {
      // ignore
    }
  }
})

Deno.test("Custom maxSlots and default scheme persist across reopen", async () => {
  await ensureTestDir()
  const path = `${testDir}/test7.pdec`
  try {
    const c1 = await PDECContainer.create({
      path,
      totalSize: 16777216,
      maxSlots: 4,
      scheme: 0x02,
      overwrite: true
    })
    const data = randomBytes(32)
    await c1.write("testpass", data)
    await c1.close()

    const c2 = await PDECContainer.open(path)
    assertEquals(c2.layout.maxSlots, 4)
    assertEquals(c2.layout.defaultScheme, 0x02)
    const slot = await c2.read("testpass")
    assert(slot)
    assertEquals(slot.data, data)
    await c2.close()
  } finally {
    try {
      await Deno.remove(path)
    } catch {
      // ignore
    }
  }
})

Deno.test("PDECContainer.create surfaces permission errors", async () => {
  await ensureTestDir()
  const readOnlyDir = `${testDir}/readonly`
  const path = `${readOnlyDir}/permission-denied.pdec`
  try {
    await Deno.mkdir(readOnlyDir, { recursive: true })
    await Deno.chmod(readOnlyDir, 0o555)
    await assertRejects(() => PDECContainer.create({ path, overwrite: true }), Error)
  } finally {
    try {
      await Deno.chmod(readOnlyDir, 0o755)
    } catch {
      // ignore
    }
    try {
      await Deno.remove(path)
    } catch {
      // ignore
    }
    try {
      await Deno.remove(readOnlyDir)
    } catch {
      // ignore
    }
  }
})
