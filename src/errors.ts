export class PDECError extends Error {
  constructor(message?: string) {
    super(message)
    this.name = this.constructor.name
  }
}

export class DecryptionFailedError extends PDECError {}
export class InvalidPassphraseError extends PDECError {}
export class ContainerTooSmallError extends PDECError {}
export class PayloadTooLargeError extends PDECError {
  readonly requiredSize: number
  readonly maxSize: number
  constructor(requiredSize: number, maxSize: number) {
    super(`Payload too large: needs ${ requiredSize } bytes, max is ${ maxSize }`)
    this.requiredSize = requiredSize
    this.maxSize = maxSize
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
    super(`Envelope version is 0x${ actualVersion.toString(16) }, expected 0x02`)
    this.actualVersion = actualVersion
  }
}
export class CollisionError extends PDECError {}
