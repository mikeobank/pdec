/**
 * Random-access IO handle interface for PDECContainer.
 */
export interface IRandomAccessHandle {
  read(offset: number, length: number): Promise<Uint8Array>
  write(offset: number, data: Uint8Array): Promise<void>
  sync(): Promise<void>
  close(): Promise<void>
  readonly size: number
}
