/**
 * Return n cryptographically random bytes.
 */
export const randomBytes = (n: number): Uint8Array => {
  const buf = new Uint8Array(n)
  const max = 65536
  for (let i = 0; i < n; i += max) {
    const chunk = i + max > n ? n - i : max
    crypto.getRandomValues(buf.subarray(i, i + chunk))
  }
  return buf
}

/**
 * Fisher-Yates shuffle of [0..n-1] using CSPRNG with rejection sampling. Never Math.random().
 */
export const shuffleIndices = (n: number): number[] => {
  const arr: number[] = Array.from({ length: n }, (_, i) => i)
  for (let i = n - 1; i > 0; i--) {
    let j = -1
    while (j === -1 || j > i) {
      const rand = randomBytes(4)
      if (rand.length < 4) throw new Error("randomBytes returned too few bytes")
      const val = (rand[0]! | (rand[1]! << 8) | (rand[2]! << 16) | (rand[3]! << 24)) >>> 0
      const max_valid = Math.floor(0xFFFFFFFF / (i + 1)) * (i + 1)
      if (val < max_valid) {
        j = val % (i + 1)
      }
    }
    // TypeScript: j is always in [0, i], so arr[j] and arr[i] are defined
    const tmp = arr[i]!
    arr[i] = arr[j]!
    arr[j] = tmp
  }
  return arr
}

/**
 * Wait a CSPRNG-derived duration between minMs and maxMs using rejection sampling.
 */
export const jitter = async (minMs: number, maxMs: number): Promise<void> => {
  if (maxMs <= minMs) {
    await new Promise((r) => setTimeout(r, minMs))
    return
  }
  const range = maxMs - minMs
  let ms = -1
  while (ms === -1 || ms > range) {
    const rand = randomBytes(4)
    if (rand.length < 4) throw new Error("randomBytes returned too few bytes")
    const val = (rand[0]! | (rand[1]! << 8) | (rand[2]! << 16) | (rand[3]! << 24)) >>> 0
    const max_valid = Math.floor(0xFFFFFFFF / (range + 1)) * (range + 1)
    if (val < max_valid) {
      ms = val % (range + 1)
    }
  }
  await new Promise((r) => setTimeout(r, minMs + ms))
}
