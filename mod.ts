// Public API barrel export for PDECContainer
export { PDECContainer } from "./src/core/container.ts"
export type { SlotData, WriteOptions } from "./src/core/container.ts"
export { computeLayout } from "./src/core/layout.ts"
export type { ContainerLayout } from "./src/core/layout.ts"
export { CONTAINER_METADATA_SIZE } from "./src/core/container_meta.ts"
export { FileHandle } from "./src/io/file-handle.ts"
export { NodeFileHandle } from "./src/io/node-file-handle.ts"
export { OPFSHandle } from "./src/io/opfs-handle.ts"
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
