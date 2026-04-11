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
 * Fisher-Yates shuffle of [0..n-1] using CSPRNG. Never Math.random().
 */
export const shuffleIndices = (n: number): number[] => {
  const arr: number[] = Array.from({ length: n }, (_, i) => i)
  for (let i = n - 1; i > 0; i--) {
    const rand = randomBytes(4)
    if (rand.length < 4) throw new Error("randomBytes returned too few bytes")
    const j = (rand[0]! | (rand[1]! << 8) | (rand[2]! << 16) | (rand[3]! << 24)) >>> 0
    const k = Math.abs(j) % (i + 1)
    // TypeScript: k is always in [0, i], so arr[k] and arr[i] are defined
    const tmp = arr[i]!
    arr[i] = arr[k]!
    arr[k] = tmp
  }
  return arr
}

/**
 * Wait a CSPRNG-derived duration between minMs and maxMs.
 */
export const jitter = async (minMs: number, maxMs: number): Promise<void> => {
  if (maxMs <= minMs) {
    await new Promise((r) => setTimeout(r, minMs))
    return
  }
  const range = maxMs - minMs
  const rand = randomBytes(4)
  if (rand.length < 4) throw new Error("randomBytes returned too few bytes")
  const val = (rand[0]! | (rand[1]! << 8) | (rand[2]! << 16) | (rand[3]! << 24)) >>> 0
  const ms = minMs + (Math.abs(val) % (range + 1))
  await new Promise((r) => setTimeout(r, ms))
}
