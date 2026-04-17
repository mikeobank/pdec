import type { IRandomAccessHandle } from "../io/types.ts"
import { jitter, randomBytes } from "../crypto/random.ts"
import { validatePassphrase } from "../passphrase/validator.ts"
import { resolveScheme, allSchemes } from "../crypto/registry.ts"
import { withKey } from "../crypto/kdf.ts"
import { deriveAddress, resolveCollision, computeRetryAddress } from "./addressing.ts"
import { buildEnvelope, parseEnvelope } from "./envelope.ts"
import { buildAAD, MAX_CIPHERTEXT_SIZE, MAX_COLLISION_RETRIES, MIN_FILE_SIZE } from "./constants.ts"
import { InvalidPassphraseError, PayloadTooLargeError } from "../errors.ts"

export interface ContainerConfig {
  readonly totalSize: number
  readonly defaultScheme: number
}

export interface ReadOptions {
  knownPassphrases?: string[]
}

export interface WriteOptions {
  scheme?: number
  knownPassphrases?: string[]
}

export interface SlotData {
  readonly data: Uint8Array
  readonly schemeId: number
  readonly writtenAt: Date
  readonly address: number
  readonly retryIndex: number
}

const DEFAULT_CONFIG: ContainerConfig = {
  totalSize: 67108864,
  defaultScheme: 0x01
}

const CHUNK_SIZE = 1048576

export class PDECContainer {
  private _handle: IRandomAccessHandle
  private _config: ContainerConfig

  private constructor(handle: IRandomAccessHandle, config: ContainerConfig) {
    this._handle = handle
    this._config = config
  }

  static async create(handle: IRandomAccessHandle, config?: Partial<ContainerConfig>): Promise<PDECContainer> {
    const cfg: ContainerConfig = { ...DEFAULT_CONFIG, ...config, totalSize: handle.size }
    if (cfg.totalSize < MIN_FILE_SIZE) throw new Error(`Container too small: minimum size is ${ MIN_FILE_SIZE } bytes`)
    let written = 0
    while (written < cfg.totalSize) {
      const chunk = Math.min(CHUNK_SIZE, cfg.totalSize - written)
      await handle.write(written, randomBytes(chunk))
      written += chunk
    }
    await handle.sync()
    return new PDECContainer(handle, cfg)
  }

  static open(handle: IRandomAccessHandle, config?: Partial<ContainerConfig>): PDECContainer {
    const cfg: ContainerConfig = { ...DEFAULT_CONFIG, ...config, totalSize: handle.size }
    return new PDECContainer(handle, cfg)
  }

  static _fromHandle(handle: IRandomAccessHandle, config?: Partial<ContainerConfig>): PDECContainer {
    const cfg: ContainerConfig = { ...DEFAULT_CONFIG, ...config, totalSize: handle.size }
    return new PDECContainer(handle, cfg)
  }

  async read(passphrase: string, _options?: ReadOptions): Promise<SlotData | undefined> {
    const derived = deriveAddress(passphrase, this._config.totalSize, 0)
    try {
      const result = await withKey(derived.encryptionKey, async key => {
        for (let k = 0; k <= MAX_COLLISION_RETRIES; k++) {
          const address = computeRetryAddress(derived.baseAddress, k, this._config.totalSize)
          const blob = await this._handle.read(address, MAX_CIPHERTEXT_SIZE)
          for (const scheme of this._schemes()) {
            const nonceBytes = scheme.nonceBytes
            const nonce = blob.subarray(0, nonceBytes)
            const ciphertext = blob.subarray(nonceBytes, nonceBytes + scheme.plaintextEnvelopeSize)
            const tag = blob.subarray(nonceBytes + scheme.plaintextEnvelopeSize, MAX_CIPHERTEXT_SIZE)
            const aad = buildAAD(address, scheme.id)
            try {
              const plaintext = await scheme.decrypt(key, nonce, ciphertext, tag, aad)
              const envelope = parseEnvelope(plaintext)
              const maxPayload = scheme.plaintextEnvelopeSize - 24
              if (envelope.payloadLen > maxPayload) continue
              return {
                data: envelope.payload,
                schemeId: envelope.schemeId,
                writtenAt: new Date(envelope.writtenAtMs),
                address,
                retryIndex: k
              } satisfies SlotData
            } catch {
              // decryption failed for this scheme/address — try next
            }
          }
        }
        return undefined
      })
      await jitter(50, 200)
      return result
    } catch {
      await jitter(50, 200)
      return undefined
    }
  }

  async write(passphrase: string, data: Uint8Array, options?: WriteOptions): Promise<void> {
    const validation = validatePassphrase(passphrase)
    if (validation.valid === false) throw new InvalidPassphraseError()

    const schemeId = options?.scheme ?? this._config.defaultScheme
    const scheme = resolveScheme(schemeId)
    const maxPayload = scheme.plaintextEnvelopeSize - 24
    if (data.length > maxPayload) throw new PayloadTooLargeError(data.length, maxPayload)

    let derived
    if (options?.knownPassphrases !== undefined && options.knownPassphrases.length > 0) {
      const others = options.knownPassphrases.filter(p => p !== passphrase)
      const existingAddresses = others.map(p => deriveAddress(p, this._config.totalSize, 0).address)
      derived = resolveCollision(passphrase, this._config.totalSize, existingAddresses)
    } else {
      derived = deriveAddress(passphrase, this._config.totalSize, 0)
    }

    const address = derived.address
    const retryIndex = derived.retryIndex
    const writtenAtMs = Date.now()
    const nonce = randomBytes(scheme.nonceBytes)
    const envelope = buildEnvelope(
      { magic: new Uint8Array(4), version: 0x02, schemeId, payloadLen: data.length, writtenAtMs, retryIndex, payload: data },
      scheme.plaintextEnvelopeSize
    )
    const aad = buildAAD(address, schemeId)

    await withKey(derived.encryptionKey, async key => {
      const { ciphertext, tag } = await scheme.encrypt(key, nonce, envelope, aad)
      const blob = new Uint8Array(MAX_CIPHERTEXT_SIZE)
      blob.set(nonce, 0)
      blob.set(ciphertext, nonce.length)
      blob.set(tag, nonce.length + ciphertext.length)
      await this._handle.write(address, blob)
    })
    await this._handle.sync()
  }

  async wipe(passphrase: string, options?: ReadOptions): Promise<boolean> {
    const found = await this.read(passphrase, options)
    if (found === undefined) return false
    await this._handle.write(found.address, randomBytes(MAX_CIPHERTEXT_SIZE))
    await this._handle.sync()
    return true
  }

  get config(): ContainerConfig {
    return this._config
  }

  async close(): Promise<void> {
    await this._handle.close()
  }

  private _schemes(): ReturnType<typeof resolveScheme>[] {
    return allSchemes()
  }
}

