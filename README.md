# PDEC: Plausibly Deniable Encrypted Container

## 1. Concept: Plausible Deniability and Why It Matters

A PDEC is a single encrypted file containing multiple independent slots, each unlocked by a different passphrase. Without the correct passphrase, all slots are indistinguishable from random data. This allows users to plausibly deny the existence of sensitive data under duress, revealing only decoy slots if necessary.

## 2. Threat Model

**Protects against:**

- Forensic analysis of the container file
- Adversaries demanding passphrases under duress
- Detection of slot count, usage, or presence of real data

**Does NOT protect against:**

- OS swap/hibernation leaking key material
- File access timestamps (use `noatime`)
- Adversaries who can snapshot the file before and after a write
- KDF runs on main thread (no Web Worker isolation)
- Memory not pinned (no mlock equivalent in Deno)

## 3. Architecture: Functional Core / Imperative Shell

```
+-------------------+      +-------------------+
|  Functional Core  |      |  Imperative Shell |
|-------------------|      |-------------------|
| - address derive  |<---->| - file IO         |
| - envelope build  |      | - jitter timing   |
| - crypto schemes  |      | - stateful handle |
| - collision check |      |                   |
+-------------------+      +-------------------+
```

## 4. Quickstart

### Create and use a container (Deno)

```ts
import { FileHandle, PDECContainer } from "./mod.ts"

// Create a new 64 MiB container
const handle = await FileHandle.create("vault.pdec", 67108864)
const container = await PDECContainer.create(handle)

// Write two secrets (collision-safe when knownPassphrases are provided)
const knownPassphrases = ["decoy12345", "realSecret🔑"]
await container.write("decoy12345", new Uint8Array([1, 2, 3]), { knownPassphrases })
await container.write("realSecret🔑", new TextEncoder().encode("Sensitive data"), { knownPassphrases })

// Read a secret
const slot = await container.read("realSecret🔑")
if (slot) {
  console.log(new TextDecoder().decode(slot.data))
}

// Wipe a secret — returns true if found and wiped, false if not found
const wiped = await container.wipe("decoy12345")

await container.close()
```

### Open an existing container

```ts
const handle = await FileHandle.open("vault.pdec")
const container = PDECContainer.open(handle)
```

An optional `ContainerConfig` second argument overrides the default scheme:

```ts
const container = PDECContainer.open(handle, { defaultScheme: 0x02 }) // XChaCha20-Poly1305
```

## 5. Storage Backends

Three `IRandomAccessHandle` implementations are provided. All expose the same `open(path)` / `create(path, size)` static factory API.

| Class | Runtime | Backing storage |
| --- | --- | --- |
| `FileHandle` | Deno | `Deno.FsFile` (seek-based) |
| `NodeFileHandle` | Node.js | `node:fs/promises` (`fh.read`/`fh.write` with byte offset) |
| `OPFSHandle` | Browser (Worker) | `FileSystemSyncAccessHandle` via Origin Private File System |

Custom backends can be plugged in by implementing `IRandomAccessHandle`.

## 6. Deno Permissions Required

- `--allow-read` and `--allow-write` for file access
- `--allow-net` for npm: dependencies (Argon2id, scrypt, XChaCha20)

## 7. Passphrase Policy Table

| Mode    | Rule                          | Entropy Notes        |
| ------- | ----------------------------- | -------------------- |
| pin     | Exactly 5 digits              | Low entropy, warning |
| unicode | ≥8 codepoints, not all-digits | Recommend >40 bits   |

## 8. Cryptographic Scheme Comparison

| ID   | KDF      | Cipher             | Nonce | Tag | Notes       |
| ---- | -------- | ------------------ | ----- | --- | ----------- |
| 0x01 | Argon2id | AES-256-GCM        | 12 B  | 16B | default     |
| 0x02 | Argon2id | XChaCha20-Poly1305 | 24 B  | 16B | large nonce |
| 0x03 | scrypt   | AES-256-GCM        | 12 B  | 16B | CPU-hard    |

## 9. Binary File Format Diagram

The container is a flat uniform blob. There are no slot boundaries,
no headers, no magic bytes, and no structural features visible to
an observer without a passphrase.

```
┌────────────────────────────────────────────────────────────┐
│  CSPRNG random bytes (initial fill)                        │
│                                                            │
│  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  │
│  ░░░░░[ NONCE | CIPHERTEXT | TAG ]░░░░░░░░░░░░░░░░░░░░░░  │ ← address(passphrase A)
│  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  │
│  ░░░░░░░░░░░░░░[ NONCE | CIPHERTEXT | TAG ]░░░░░░░░░░░░░  │ ← address(passphrase B)
│  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  │
└────────────────────────────────────────────────────────────┘

Each NONCE | CIPHERTEXT | TAG region is exactly MAX_CIPHERTEXT_SIZE (64 KiB) bytes.
Its location is derived from the passphrase — not from file structure.
Without the passphrase, the region is unlocatable and indistinguishable
from surrounding random bytes.

Inside the AEAD envelope (decrypted):
Offset  Size  Field
──────────────────────────────────────────────────────────────────
 0       4    Magic: 0xDE 0xC0 0x1A 0x57  (post-decrypt sanity check)
 4       1    Format version: 0x02
 5       1    Scheme ID (0x01 | 0x02 | 0x03)
 6       2    Reserved: 0x00 0x00
 8       4    Actual payload byte length (uint32 LE)
 12      8    Write timestamp Unix ms (uint64 LE)
 20      4    Retry index used at write time (uint32 LE)
 24    varies Actual payload bytes
 ...   varies CSPRNG random padding
```

## 10. Security Properties

- **Passphrase-derived addressing:** Address is secret, derived from passphrase via Argon2id. Without the passphrase, no candidate region can be identified for probing. ([src/core/addressing.ts])
- **Fixed ciphertext size:** All writes are exactly MAX_CIPHERTEXT_SIZE (64 KiB) bytes. Payload length is hidden inside the AEAD envelope. ([src/core/constants.ts])
- **No occupancy metadata:** The file contains no slot count, allocation map, or any structure visible without a passphrase. ([src/core/container.ts])
- **AAD address binding:** buildAAD includes the derived address, preventing an attacker from relocating a ciphertext blob to a different offset. ([src/core/constants.ts])
- **CSPRNG initialisation:** The entire file is random bytes at creation. Occupied and unoccupied regions are indistinguishable. ([src/core/container.ts])
- **Timing jitter:** Random delay of 50–200 ms applied unconditionally after every read attempt. ([src/crypto/random.ts], [src/core/container.ts])
- **No oracle errors:** All failures return undefined. ([src/core/container.ts])
- **CSPRNG wipe:** Overwrites use randomBytes, not zeroes. ([src/crypto/random.ts])
- **Key zeroing:** withKey always zeroes key buffer; full 64-byte material buffer zeroed after slicing. ([src/crypto/kdf.ts])
- **No secret leakage:** No passphrase or key in errors/logs. ([src/errors.ts])
- **Null boundary rule:** Only undefined, never null. ([src/errors.ts], [src/io/file-handle.ts])

## 11. Known Limitations

- OS swap/hibernation may expose key material
- File access timestamps leak usage (use noatime)
- KDF runs on caller thread, no Web Worker isolation
- No mlock equivalent in Deno (memory not pinned)
- Minimum container size: 4 MiB (`MIN_FILE_SIZE`). Smaller files are rejected at creation time.
- File change detection: adversary who snapshots before and after a write can confirm a region was modified
- Collision probability: with default settings (64 MiB file, 64 KiB max ciphertext, 8 secrets), the probability of any two secrets colliding is approximately 6.25%. Pass `knownPassphrases` to `write()` to enable active collision detection and resolution.
- Collision detection requires revealing other passphrases to the `write()` call. If this is unacceptable for your threat model, omit `knownPassphrases` and accept the ~6% collision probability, or increase container `totalSize`.
- Retry index in envelope: if collision detection displaced a write to a retry address, `read()` still locates it by trying all `MAX_COLLISION_RETRIES` (8) addresses sequentially — no `knownPassphrases` needed for reads.

## 12. Running Tests

```
deno task test                        # all tests
deno test tests/container.test.ts     # single file
```

Test files follow the *.test.ts naming convention.

## 13. Dependency Rationale

- **@noble/hashes** and **@noble/ciphers**: Audited, zero dependencies, no WASM, pure TypeScript.

## 14. License

MIT
