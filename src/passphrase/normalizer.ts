/**
 * NFC-normalize a passphrase before any KDF operation.
 * 'e\u0301' and '\u00e9' must produce identical KDF input.
 */
export const normalizePassphrase = (input: string): string => {
  return input.normalize("NFC")
}
