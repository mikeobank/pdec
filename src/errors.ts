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
export class UnknownSchemeError extends PDECError {}
export class SchemeAlreadyRegisteredError extends PDECError {}
export class IOError extends PDECError {
  override readonly cause?: unknown
  constructor(message?: string, cause?: unknown) {
    super(message)
    this.cause = cause
  }
}
export class VersionMismatchError extends PDECError {}
