/**
 * Passphrase mode: 'pin' or 'unicode'.
 */
export type PassphraseMode = "pin" | "unicode"

export interface PassphraseValidationResult {
  readonly valid: boolean
  readonly mode: PassphraseMode
  readonly warnings: string[]
  readonly errors: string[]
}

/**
 * Validate a passphrase string. Pure function — no IO, no side effects.
 * PIN mode:     /^\d{5}$/ exactly. Emits low-entropy warning.
 * Unicode mode: [...str].length >= 8 codepoints. Rejects all-digit strings
 *               of any length (user must use PIN mode explicitly).
 *               Rejects whitespace-only strings.
 */
export const validatePassphrase = (input: string): PassphraseValidationResult => {
  const warnings: string[] = []
  const errors: string[] = []
  const codepoints = [...input]
  if (/^\d{5}$/.test(input)) {
    warnings.push("PIN mode: low entropy")
    return { valid: true, mode: "pin", warnings, errors }
  }
  if (/^\d+$/.test(input)) {
    errors.push("All-digit string not allowed in unicode mode")
    return { valid: false, mode: "unicode", warnings, errors }
  }
  if (codepoints.length < 8) {
    errors.push("Passphrase must be at least 8 codepoints")
    return { valid: false, mode: "unicode", warnings, errors }
  }
  if (/^\s+$/.test(input)) {
    errors.push("Whitespace-only passphrase not allowed")
    return { valid: false, mode: "unicode", warnings, errors }
  }
  return { valid: true, mode: "unicode", warnings, errors }
}
