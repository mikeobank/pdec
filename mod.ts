// Public API barrel export for PDECContainer
export { PDECContainer } from "./src/core/container.ts"
export type { PDECCreateOptions, SlotData, WriteOptions } from "./src/core/container.ts"
export {
  ContainerFullError,
  ContainerTooSmallError,
  DecryptionFailedError,
  InvalidLayoutError,
  InvalidPassphraseError,
  IOError,
  PayloadTooLargeError,
  PDECError,
  SchemeAlreadyRegisteredError,
  UnknownSchemeError,
  VersionMismatchError
} from "./src/errors.ts"
export { estimateEntropy } from "./src/passphrase/strength.ts"
