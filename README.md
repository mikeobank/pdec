# PDEC: Plausibly Deniable Encrypted Container for Deno

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
| - layout math     |<---->| - file IO         |
| - header parsing  |      | - slot scan order |
| - crypto schemes  |      | - jitter timing   |
| - slot scanning   |      | - stateful handle |
+-------------------+      +-------------------+
```

## 4. Quickstart
```ts
import { PDECContainer } from './mod.ts';

// Create a new container
const container = await PDECContainer.create({ path: 'vault.pdec', overwrite: true });

// Write two slots
await container.write('decoy12345', new Uint8Array([1, 2, 3]));
await container.write('realSecret🔑', new TextEncoder().encode('Sensitive data'));

// Read a slot
const slot = await container.read('realSecret🔑');
if (slot) {
  console.log(new TextDecoder().decode(slot.data));
}

// Wipe a slot
await container.wipe('decoy12345');

await container.close();
```

## 5. Deno Permissions Required
- `--allow-read` and `--allow-write` for file access
- `--allow-net` for npm: dependencies (Argon2id, scrypt, XChaCha20)

## 6. Passphrase Policy Table
| Mode    | Rule                        | Entropy Notes           |
|---------|-----------------------------|-------------------------|
| pin     | Exactly 5 digits            | Low entropy, warning    |
| unicode | ≥8 codepoints, not all-digits| Recommend >40 bits      |

## 7. Cryptographic Scheme Comparison
| ID   | KDF      | Cipher             | Nonce | Tag | Notes       |
|------|----------|--------------------|-------|-----|-------------|
| 0x01 | Argon2id | AES-256-GCM        | 12 B  | 16B | default     |
| 0x02 | Argon2id | XChaCha20-Poly1305 | 24 B  | 16B | large nonce |
| 0x03 | scrypt   | AES-256-GCM        | 12 B  | 16B | CPU-hard    |

## 8. Binary File Format Diagram
```
[ CONTAINER METADATA | SLOT 0 | SLOT 1 | ... ]
 64 bytes             fixed-size records

Inside each slot:
[ PLAINTEXT HEADER | OPTIONAL EXTENDED NONCE BYTES | ENCRYPTED PAYLOAD+TAG | RANDOM PADDING ]
 64 bytes           scheme.nonceBytes-12           data + tag bytes        remaining padding

Slot header structure (64 bytes, plaintext, NOT inside AEAD):
Offset  Size  Field
─────────────────────────────────────────────
0       4    Magic: 0xDE 0xC0 0x1A 0x57
4       1    Version: 0x01
5       1    Scheme ID
6       1    Allocated flag: 1 = in-use, 0 = free
7       1    Reserved: 0x00
8      16    KDF salt
24     12    AEAD nonce (12 bytes; 24-byte nonce in payload)
36      4    Payload length (LE)
40      8    Write timestamp (uint64 LE)
48     16    Slot nonce (mixed with passphrase for KDF)
──────────────────────────────
64     HEADER_SIZE

AEAD ciphertext+tag (all encrypted):
[optional extended nonce bytes are stored before ciphertext in the slot body]
[ciphertext for payload][AEAD authentication tag]
```

## 9. Security Properties
- **Full slot scan:** All slots are always scanned, never early return. ([src/slot/scanner.ts])
- **Timing jitter:** Random delay after scan. ([src/crypto/random.ts], [src/core/container.ts])
- **Random scan order:** Indices shuffled with CSPRNG. ([src/crypto/random.ts])
- **No oracle errors:** All failures return undefined. ([src/slot/scanner.ts])
- **CSPRNG wipe:** Overwrites use randomBytes, not zeroes. ([src/crypto/random.ts])
- **Key zeroing:** withKey always zeroes key buffer. ([src/crypto/kdf.ts])
- **AAD location binding:** buildAAD binds slot index. ([src/core/constants.ts])
- **No secret leakage:** No passphrase or key in errors/logs. ([src/errors.ts])
- **Null boundary rule:** Only undefined, never null. ([src/errors.ts], [src/io/file-handle.ts])

## 10. Known Limitations
- OS swap/hibernation may expose key material
- File access timestamps leak usage (use noatime)
- KDF runs on caller thread, no Web Worker isolation
- No mlock equivalent in Deno (memory not pinned)
- File change detection: adversary who snapshots before and after a write can confirm a slot was modified

## 11. Running Tests
```
deno task test                        # all tests
deno test tests/container.test.ts     # single file
```
Test files follow the *.test.ts naming convention.

## 12. Dependency Rationale
- **@noble/hashes** and **@noble/ciphers**: Audited, zero dependencies, no WASM, pure TypeScript.

## 13. License
MIT
