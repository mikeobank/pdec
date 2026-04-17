export { PDECContainer } from "./src/core/container.ts"
export type { ContainerConfig, ReadOptions, SlotData, WriteOptions } from "./src/core/container.ts"
export { FileHandle } from "./src/io/file-handle.ts"
export { NodeFileHandle } from "./src/io/node-file-handle.ts"
export { OPFSHandle } from "./src/io/opfs-handle.ts"
export {
  CollisionError,
  ContainerTooSmallError,
  DecryptionFailedError,
  InvalidPassphraseError,
  IOError,
  PayloadTooLargeError,
  PDECError,
  SchemeAlreadyRegisteredError,
  UnknownSchemeError,
  VersionMismatchError
} from "./src/errors.ts"
export { estimateEntropy } from "./src/passphrase/strength.ts"
