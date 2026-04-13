/**
 * Base error for all PDEC errors.
 */
export class PDECError extends Error {
  constructor(message?: string) {
    super(message)
    this.name = this.constructor.name
  }
}

export class DecryptionFailedError extends PDECError {}
export class InvalidPassphraseError extends PDECError {}
export class ContainerFullError extends PDECError {}
export class ContainerTooSmallError extends PDECError {}
export class InvalidLayoutError extends PDECError {}
export class PayloadTooLargeError extends PDECError {
  readonly requiredSize: number
  readonly slotSize: number
  constructor(requiredSize: number, slotSize: number) {
    super(`Payload too large: needs ${requiredSize} bytes, slot size is ${slotSize}`)
    this.requiredSize = requiredSize
    this.slotSize = slotSize
  }
}
export class UnknownSchemeError extends PDECError {}
export class SchemeAlreadyRegisteredError extends PDECError {}
export class IOError extends PDECError {
  override readonly cause?: unknown
  constructor(message?: string, cause?: unknown) {
    super(message)
    this.cause = cause
  }
}
export class VersionMismatchError extends PDECError {
  readonly actualVersion: number
  constructor(actualVersion: number) {
    super(`Header version is 0x${actualVersion.toString(16)}, expected 0x01`)
    this.actualVersion = actualVersion
  }
}
