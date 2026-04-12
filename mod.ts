// Public API barrel export for PDECContainer
export { PDECContainer } from "./src/core/container.ts"
export type { PDECCreateOptions, WriteOptions, SlotData } from "./src/core/container.ts"
export {
  PDECError,
  DecryptionFailedError,
  InvalidPassphraseError,
  ContainerFullError,
  ContainerTooSmallError,
  InvalidLayoutError,
  PayloadTooLargeError,
  UnknownSchemeError,
  SchemeAlreadyRegisteredError,
  IOError,
  VersionMismatchError
} from "./src/errors.ts"
export { estimateEntropy } from "./src/passphrase/strength.ts"
