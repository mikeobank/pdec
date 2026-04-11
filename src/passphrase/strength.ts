/**
 * Estimate passphrase entropy in bits. Returns a rough estimate only —
 * used for warnings, not enforcement. No external dependencies.
 */
export const estimateEntropy = (input: string): number => {
  if (input.length === 0) return 0
  const codepoints = [...input]
  const unique = new Set(codepoints)
  // Simple model: log2(unique chars) * length
  const log2 = (n: number) => Math.log(n) / Math.LN2
  return Math.round(log2(unique.size) * codepoints.length)
}
