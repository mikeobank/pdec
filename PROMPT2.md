The goal of this update is to replace the current fixed-slot addressing
scheme with passphrase-derived slot addressing, so that an attacker with
access to the container file cannot determine how many secrets are stored,
which regions are occupied, or whether any secret exists — even after
observing the file at multiple points in time.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BACKGROUND: WHY THE CURRENT DESIGN LEAKS OCCUPANCY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The current implementation stores a plaintext slot header at the start of
each fixed-size slot region. This header contains:
  - Magic bytes 0xDE 0xC0 0x1A 0x57 at offset 0 (plaintext)
  - An allocated flag at offset 6 (plaintext)
  - Fixed slot boundaries computable from file size alone

An attacker can:
  1. Scan all slot-aligned offsets for the magic bytes and allocated flag,
     immediately revealing exactly which slots are occupied without any key.
  2. Compute slot boundaries from file size and maxSlots, then probe each
     region for valid AEAD tags using their own known passphrase.
  3. Observe the file at two timestamps and identify exactly which
     slot-aligned region changed, confirming a write location.

The fix is to make slot location itself a secret derived from the passphrase,
so that without the passphrase an attacker has no candidate region to probe.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CORE DESIGN CHANGE: PASSPHRASE-DERIVED ADDRESSING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Replace fixed slot geometry with a flat uniform blob and passphrase-derived
addresses. The complete new model:

  1. The container file is entirely CSPRNG random bytes at creation time.
     There are no slots, no boundaries, no headers, no magic bytes, no
     allocated flags anywhere on disk. The file has no structure.

  2. Each passphrase derives its own secret address and encryption key
     from a single expanded KDF call:

       material (64 bytes) = Argon2id(
         password : normalizePassphrase(passphrase),
         salt     : DOMAIN_SALT,           // 32-byte public constant, not secret
         m        : 65536  (unicode mode)
                    262144 (pin mode),
         t        : 3      (unicode mode)
                    10     (pin mode),
         p        : 1,
         dkLen    : 64,
       )

       encryptionKey  = material[0..31]    // 32 bytes → AES-256 or ChaCha20 key
       addressSeed    = material[32..39]   // 8 bytes → derive file offset
       schemeSeed     = material[40..40]   // 1 byte  → derive default scheme
         (schemeSeed is advisory; the actual schemeId is stored inside AEAD)

       addressableRange = totalSize - MAX_CIPHERTEXT_SIZE
       address = readUint32LE(addressSeed) % addressableRange
                 // address is aligned down to BLOCK_ALIGN (= 64) bytes:
                 address = Math.floor(address / BLOCK_ALIGN) * BLOCK_ALIGN

  3. To write a secret: encrypt the payload envelope at the derived address,
     overwriting whatever bytes are there. No header is written outside the
     AEAD envelope.

  4. To read a secret: derive the same address and key, read
     MAX_CIPHERTEXT_SIZE bytes from that offset, attempt AEAD decryption.
     Return the payload on success, undefined on failure.

  5. MAX_CIPHERTEXT_SIZE is a fixed public constant. Every write pads the
     plaintext envelope to a fixed size before encryption, so all
     ciphertexts on disk are exactly MAX_CIPHERTEXT_SIZE bytes regardless
     of actual payload length. This prevents length-based correlation.

     Default: MAX_CIPHERTEXT_SIZE = 65536  (64 KiB)
     This means max usable payload ≈ 65536 - ENVELOPE_OVERHEAD bytes.

  6. DOMAIN_SALT is a fixed 32-byte public constant defined in constants.ts.
     It is NOT secret. Its purpose is domain separation — it ensures that
     key material derived here is distinct from key material derived by any
     other application using the same password. It is hardcoded and never
     written to the container file.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COLLISION HANDLING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Two passphrases may derive overlapping address ranges. If passphrase A's
ciphertext region overlaps passphrase B's and B is written after A, B's
write will corrupt A's ciphertext making A unreadable.

Implement the following two-tier collision strategy:

── TIER 1: Probabilistic safety by design ─────────────────────

  With a 64 MiB file, MAX_CIPHERTEXT_SIZE = 64 KiB, and up to 8 secrets:

    P(any collision among n secrets)
      ≈ n² × MAX_CIPHERTEXT_SIZE / totalSize
      = 64 × 65536 / 67108864
      ≈ 6.25%

  This is acceptable for most use cases. Document it clearly in README.md
  under Known Limitations. No on-disk metadata is needed for this tier.

── TIER 2: Active collision detection at write time ───────────

  The write() method accepts an optional `knownPassphrases: string[]`
  parameter. When provided, the library:

    1. Derives the candidate address for the new passphrase.
    2. For each passphrase in knownPassphrases (excluding the write target),
       derives its address.
    3. Checks whether any existing address range
         [existingAddr, existingAddr + MAX_CIPHERTEXT_SIZE)
       overlaps with
         [candidateAddr, candidateAddr + MAX_CIPHERTEXT_SIZE).
    4. If overlap detected, increment candidateAddr by MAX_CIPHERTEXT_SIZE
       and re-check, up to MAX_COLLISION_RETRIES = 8 times.
       Address wraps modulo addressableRange, re-aligned to BLOCK_ALIGN.
    5. If no non-overlapping address is found after MAX_COLLISION_RETRIES,
       throw CollisionError (a new error subclass of PDECError).
    6. Write the ciphertext at the final non-overlapping address.

  When knownPassphrases is not provided, write proceeds without collision
  detection (Tier 1 only). This preserves the ability to use the API
  without revealing other passphrases to the library.

  CRITICAL DENIABILITY CONSTRAINT: No collision map, reservation table,
  or address index is ever written to the container file. The only thing
  written is the fixed-size ciphertext blob at the derived address.
  Collision detection is purely in-memory and ephemeral.

── Collision retry address derivation ─────────────────────────

  On retry k (starting at k=0 for the base address):

    retryAddress = (baseAddress + k * MAX_CIPHERTEXT_SIZE) % addressableRange
    retryAddress = Math.floor(retryAddress / BLOCK_ALIGN) * BLOCK_ALIGN

  This is deterministic given the passphrase and k, so the same retry
  address is always reachable on subsequent reads without storing anything.
  The read() method does NOT need to know about retries — it derives the
  base address and reads from there. Retried writes are a write-time concern
  only; if a collision displaced the write, the displaced address is only
  findable by re-running collision detection with the same knownPassphrases.

  THEREFORE: If Tier 2 collision detection was used at write time, the
  caller must pass the same knownPassphrases to read() so the library can
  re-derive the displaced address. Make this explicit in the API and docs.

  read() signature update:
    async read(
      passphrase: string,
      options?: ReadOptions,
    ): Promise<SlotData | undefined>

  ReadOptions:
    knownPassphrases?: string[]   // required if write used collision detection

  The read() method tries addresses in order:
    address_0 (base), address_1 (first retry), ..., up to MAX_COLLISION_RETRIES
  returning the first successful AEAD decryption.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PLAINTEXT ENVELOPE FORMAT (inside AEAD)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The AEAD plaintext is a fixed-size envelope of exactly
  PLAINTEXT_ENVELOPE_SIZE = MAX_CIPHERTEXT_SIZE - NONCE_SIZE - TAG_SIZE
bytes. Its layout:

  Offset  Size  Field
  ──────────────────────────────────────────────────────────────────
   0       4    Magic: 0xDE 0xC0 0x1A 0x57  (post-decrypt sanity check only)
   4       1    Format version: 0x02         (bumped from 0x01)
   5       1    Scheme ID (0x01 | 0x02 | 0x03)
   6       2    Reserved: 0x00 0x00
   8       4    Actual payload byte length (uint32 LE, DataView)
   12      8    Write timestamp Unix ms (uint64 LE, two uint32 DataView writes)
   20      4    Retry index used at write time (uint32 LE) — 0 if no retry
   24    varies Actual payload bytes (length = payloadLen field above)
   ...   varies Random CSPRNG padding to fill remaining PLAINTEXT_ENVELOPE_SIZE

The nonce (12 or 24 bytes depending on scheme) is stored OUTSIDE the AEAD
envelope, prepended to the ciphertext on disk:

  On disk at derived address:
  [ NONCE (nonceBytes) | CIPHERTEXT (PLAINTEXT_ENVELOPE_SIZE) | TAG (16) ]
  Total = NONCE_SIZE + PLAINTEXT_ENVELOPE_SIZE + 16 = MAX_CIPHERTEXT_SIZE

The nonce is randomly generated per write and stored in plaintext — this
is standard AEAD practice. Nonce exposure does not compromise confidentiality
or deniability since without the key the ciphertext is indistinguishable
from random, and the nonce itself is indistinguishable from the surrounding
random bytes of an unoccupied region.

AEAD additional data (AAD) binds the ciphertext to its derived address:
  buildAAD(address, schemeId) = DOMAIN_MAGIC(4) || uint32LE(address)(4) || schemeId(1)
  Total: 9 bytes

This prevents an attacker from copying the ciphertext blob to a different
offset and having it authenticate. Update buildAAD() signature accordingly —
it now takes address (number) instead of slotIndex (number).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FILES TO DELETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Delete these files entirely — their concepts no longer exist:

  src/core/layout.ts          (fixed slot geometry replaced by derived addressing)
  src/core/header.ts          (plaintext header replaced by AEAD envelope)
  src/core/container_meta.ts  (container metadata block no longer exists)
  src/slot/scanner.ts         (slot scanning over fixed offsets replaced)
  src/slot/allocator.ts       (slot allocation replaced by address derivation)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FILES TO CREATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

src/core/addressing.ts
  Pure functions. No IO. No class syntax.

  export interface DerivedAddress {
    readonly encryptionKey:  Uint8Array;  // 32 bytes — zero after use via withKey
    readonly address:        number;      // byte offset in file, BLOCK_ALIGN-aligned
    readonly baseAddress:    number;      // address before retry (same as address if k=0)
    readonly retryIndex:     number;      // k used (0 = no retry)
  }

  /** Derive encryption key and file address from a passphrase.
   *  Single Argon2id call producing 64 bytes of key material.
   *  address is aligned down to BLOCK_ALIGN bytes.
   *  retryIndex 0 = base address, 1..MAX_COLLISION_RETRIES = retry offsets. */
  export async function deriveAddress(
    passphrase:   string,
    totalSize:    number,
    retryIndex?:  number,   // default 0
  ): Promise<DerivedAddress>

  /** Check whether two address ranges of MAX_CIPHERTEXT_SIZE overlap. */
  export function rangesOverlap(addrA: number, addrB: number): boolean

  /** Given a candidate passphrase and a list of existing passphrases,
   *  find the lowest retry index (0..MAX_COLLISION_RETRIES) that produces
   *  a non-overlapping address. Throws CollisionError if none found.
   *  Pure function — caller provides pre-derived existing addresses. */
  export async function resolveCollision(
    passphrase:       string,
    totalSize:        number,
    existingAddresses: number[],
  ): Promise<DerivedAddress>

src/core/envelope.ts
  Pure functions. No IO. No class syntax.

  export interface EnvelopeData {
    readonly magic:       Uint8Array;   // 4 bytes
    readonly version:     number;       // 0x02
    readonly schemeId:    number;
    readonly payloadLen:  number;
    readonly writtenAtMs: number;
    readonly retryIndex:  number;
    readonly payload:     Uint8Array;   // actual content, not padded
  }

  /** Build the fixed-size PLAINTEXT_ENVELOPE_SIZE byte buffer from EnvelopeData.
   *  Pads payload with CSPRNG random bytes to fill remaining space. */
  export function buildEnvelope(data: EnvelopeData): Uint8Array

  /** Parse PLAINTEXT_ENVELOPE_SIZE bytes into EnvelopeData.
   *  Throws VersionMismatchError if version != 0x02.
   *  Validates magic post-decrypt (throws DecryptionFailedError if wrong). */
  export function parseEnvelope(bytes: Uint8Array): EnvelopeData

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FILES TO MODIFY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

src/core/constants.ts
  Remove: HEADER_SIZE, slot geometry constants, slotIndex-based buildAAD.
  Add:
    export const VERSION                = 0x02;
    export const BLOCK_ALIGN            = 64;
    export const MAX_CIPHERTEXT_SIZE    = 65536;       // 64 KiB, fixed
    export const MAX_COLLISION_RETRIES  = 8;
    export const MIN_FILE_SIZE          = 4194304;     // 4 MiB minimum
    export const DOMAIN_SALT: Uint8Array               // 32 hardcoded bytes,
      // e.g. SHA-256("pdec-domain-salt-v2") computed once and hardcoded as literal
    export const DOMAIN_MAGIC           = new Uint8Array([0xDE, 0xC0, 0x1A, 0x57]);

    /** Build the 9-byte AAD binding ciphertext to its derived address. */
    export function buildAAD(address: number, schemeId: number): Uint8Array
      // DOMAIN_MAGIC(4) || uint32LE(address)(4) || schemeId(1)

    export const NONCE_SIZE_AES     = 12;
    export const NONCE_SIZE_XCHACHA = 24;
    export const TAG_SIZE           = 16;
    export const PLAINTEXT_ENVELOPE_SIZE =
      MAX_CIPHERTEXT_SIZE - NONCE_SIZE_AES - TAG_SIZE;
      // Note: XChaCha20 uses 24-byte nonce, so its PLAINTEXT_ENVELOPE_SIZE differs.
      // Store scheme-specific PLAINTEXT_ENVELOPE_SIZE on the ICryptoScheme object
      // as readonly plaintextEnvelopeSize: number.

src/core/container.ts
  Rewrite entirely. Keep PDECContainer as the only class. Keep _fromHandle.
  Remove all references to layout, slots, slotOffset, scanSlots, findFreeSlot.
  Replace with calls to deriveAddress, resolveCollision, buildEnvelope,
  parseEnvelope, and the IO handle.

  Updated interface:

  export interface ContainerConfig {
    readonly totalSize:     number;   // must be >= MIN_FILE_SIZE
    readonly defaultScheme: number;   // default 0x01
  }

  export interface ReadOptions {
    knownPassphrases?: string[];  // required when write used collision detection
  }

  export interface WriteOptions {
    scheme?:            number;     // per-secret scheme override
    knownPassphrases?:  string[];   // enables Tier 2 collision detection
  }

  export interface SlotData {       // keep name SlotData for API compatibility
    readonly data:        Uint8Array;
    readonly schemeId:    number;
    readonly writtenAt:   Date;
    readonly address:     number;   // replaces slotIndex — derived file offset
    readonly retryIndex:  number;   // 0 if no collision retry was needed
  }

  PDECContainer methods:

  static async create(
    handle:  IRandomAccessHandle,
    config?: Partial<ContainerConfig>,
  ): Promise<PDECContainer>
  // Fill entire handle with randomBytes() in CHUNK_SIZE blocks (e.g. 1 MiB)
  // to avoid allocating totalSize in memory at once.

  static async open(
    handle: IRandomAccessHandle,
    config?: Partial<ContainerConfig>,
  ): Promise<PDECContainer>
  // No validation — the file has no plaintext structure to validate.
  // Infer totalSize from handle.size.

  static _fromHandle(
    handle: IRandomAccessHandle,
    config: ContainerConfig,
  ): PDECContainer

  async read(
    passphrase: string,
    options?:   ReadOptions,
  ): Promise<SlotData | undefined>
  // 1. Derive candidate addresses (base + retries if knownPassphrases provided)
  // 2. For each candidate address (in order 0..MAX_COLLISION_RETRIES):
  //    a. Read MAX_CIPHERTEXT_SIZE bytes from that offset
  //    b. Split into nonce | ciphertext | tag
  //    c. Derive key from passphrase (using deriveAddress)
  //    d. Attempt AEAD decrypt with buildAAD(address, schemeId)
  //    e. On success: parseEnvelope, validate magic, return SlotData
  //    f. On failure: continue to next retry index
  // 3. Apply jitter(50, 200) before returning regardless of outcome
  // 4. Return undefined if all attempts fail

  async write(
    passphrase: string,
    data:       Uint8Array,
    options?:   WriteOptions,
  ): Promise<void>
  // 1. validatePassphrase — throw InvalidPassphraseError if invalid
  // 2. If options.knownPassphrases provided: resolveCollision to find address
  //    Else: deriveAddress with retryIndex 0
  // 3. buildEnvelope with the payload (padded to PLAINTEXT_ENVELOPE_SIZE)
  // 4. Generate fresh nonce (randomBytes(scheme.nonceBytes))
  // 5. Encrypt envelope with buildAAD(address, schemeId)
  // 6. Write [nonce | ciphertext | tag] at derived address
  // 7. sync()

  async wipe(passphrase: string, options?: ReadOptions): Promise<boolean>
  // 1. Try to find address by attempting read (same retry logic as read())
  // 2. If found: overwrite MAX_CIPHERTEXT_SIZE bytes at that address with
  //    randomBytes(MAX_CIPHERTEXT_SIZE), then sync()
  // 3. Return true if wiped, false if passphrase had no secret

  get config(): ContainerConfig
  async close(): Promise<void>

src/crypto/kdf.ts
  Add a new exported function used by deriveAddress:

  /** Single Argon2id call producing 64 bytes of key material for
   *  passphrase-derived addressing. Uses DOMAIN_SALT, not a random salt.
   *  Adjusts cost for PIN mode. */
  export async function deriveAddressMaterial(
    passphrase: string,
    mode:       PassphraseMode,
  ): Promise<Uint8Array>   // always 64 bytes; caller must zero after use

  Keep existing deriveKeyArgon2, deriveKeyScrypt, withKey unchanged.

src/crypto/schemes/types.ts
  Add to ICryptoScheme:
    readonly plaintextEnvelopeSize: number;
    // = MAX_CIPHERTEXT_SIZE - nonceBytes - tagBytes

  Update all three scheme objects to include this field.

src/errors.ts
  Add:
  /** Thrown when collision resolution exhausts MAX_COLLISION_RETRIES. */
  class CollisionError extends PDECError

  Remove: ContainerFullError (no longer applicable — there is no slot count limit)

mod.ts
  Remove exports: computeLayout, CONTAINER_METADATA_SIZE, ContainerFullError
  Add exports:    CollisionError
  Update SlotData type export (address field replaces slotIndex)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FILES TO KEEP UNCHANGED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  src/crypto/registry.ts          no change
  src/crypto/schemes/*.ts         add plaintextEnvelopeSize field only
  src/crypto/random.ts            no change
  src/passphrase/validator.ts     no change
  src/passphrase/normalizer.ts    no change
  src/passphrase/strength.ts      no change
  src/io/types.ts                 no change
  src/io/file-handle.ts           no change
  src/io/buffer-handle.ts         no change
  src/io/node-file-handle.ts      no change
  src/io/opfs-handle.ts           no change
  deno.json                       no change
  deno.lock                       regenerate after any dep changes

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
UPDATED TESTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Delete: tests/layout.test.ts  (fixed layout no longer exists)
Delete: tests/slot.test.ts    (fixed slots no longer exist)

Replace with: tests/addressing.test.ts

  Deno.test('deriveAddress: same passphrase produces same address and key')
  Deno.test('deriveAddress: different passphrases produce different addresses')
  Deno.test('deriveAddress: address is within [0, totalSize - MAX_CIPHERTEXT_SIZE)')
  Deno.test('deriveAddress: address is aligned to BLOCK_ALIGN bytes')
  Deno.test('deriveAddress: retryIndex 1 produces address offset by MAX_CIPHERTEXT_SIZE')
  Deno.test('deriveAddress: PIN mode uses higher Argon2id cost than unicode mode')
  Deno.test('rangesOverlap: returns true for overlapping ranges')
  Deno.test('rangesOverlap: returns false for adjacent non-overlapping ranges')
  Deno.test('resolveCollision: finds non-overlapping address when base collides')
  Deno.test('resolveCollision: throws CollisionError after MAX_COLLISION_RETRIES')
  Deno.test('buildEnvelope: round-trip with parseEnvelope returns original payload')
  Deno.test('buildEnvelope: output is always PLAINTEXT_ENVELOPE_SIZE bytes')
  Deno.test('buildEnvelope: padding is random (two calls differ in padding bytes)')
  Deno.test('parseEnvelope: wrong magic after decryption throws DecryptionFailedError')
  Deno.test('parseEnvelope: version 0x01 throws VersionMismatchError')

Update: tests/container.test.ts
  Remove all tests referencing slotIndex, maxSlots, ContainerFullError, layout.
  Add:

  Deno.test('write and read round-trip — scheme 0x01 AES-GCM+Argon2id')
  Deno.test('write and read round-trip — scheme 0x02 XChaCha20+Argon2id')
  Deno.test('write and read round-trip — scheme 0x03 AES-GCM+scrypt')
  Deno.test('read returns undefined for wrong passphrase')
  Deno.test('read returns undefined on completely empty container')
  Deno.test('wipe makes secret unreadable — read returns undefined after wipe')
  Deno.test('wipe returns false when passphrase has no secret')
  Deno.test('two secrets are independently readable')
  Deno.test('overwriting a secret preserves the other secret')
  Deno.test('write with 5-digit PIN passphrase succeeds')
  Deno.test('write with Unicode passphrase containing emoji succeeds')
  Deno.test('write with Unicode passphrase containing CJK characters succeeds')
  Deno.test('write with Unicode passphrase containing RTL characters succeeds')
  Deno.test('SlotData.writtenAt is within 5 seconds of current time')
  Deno.test('SlotData.schemeId matches the scheme used to write')
  Deno.test('SlotData.address matches derived address for that passphrase')
  Deno.test('SlotData.retryIndex is 0 when no collision detection used')
  Deno.test('collision detection: write with knownPassphrases avoids overlap')
  Deno.test('collision detection: read with knownPassphrases finds displaced secret')
  Deno.test('file bytes at unoccupied addresses are indistinguishable from ciphertext')
  Deno.test('read duration >= 50ms due to jitter even on empty container')

Keep unchanged: tests/crypto.test.ts, tests/passphrase.test.ts

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
UPDATED README.md SECTIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Rewrite these sections in full. All other sections remain.

Section 8 — Binary file format diagram:
  Replace fixed-slot diagram with:

  The container is a flat uniform blob. There are no slot boundaries,
  no headers, no magic bytes, and no structural features visible to
  an observer without a passphrase.

  ┌────────────────────────────────────────────────────────────┐
  │  CSPRNG random bytes (initial fill)                        │
  │                                                            │
  │  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  │
  │  ░░░░░[ NONCE | CIPHERTEXT | TAG ]░░░░░░░░░░░░░░░░░░░░░░  │ ← address(passphrase A)
  │  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  │
  │  ░░░░░░░░░░░░░░[ NONCE | CIPHERTEXT | TAG ]░░░░░░░░░░░░░  │ ← address(passphrase B)
  │  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  │
  └────────────────────────────────────────────────────────────┘

  Each NONCE | CIPHERTEXT | TAG region is exactly MAX_CIPHERTEXT_SIZE bytes.
  Its location is derived from the passphrase — not from file structure.
  Without the passphrase, the region is unlocatable and indistinguishable
  from surrounding random bytes.

Section 9 — Security properties:
  Remove: full slot scan, random scan order (no longer applicable)
  Add:
  - Passphrase-derived addressing: address is secret, derived from passphrase.
    Without the passphrase, no candidate region can be identified for probing.
  - Fixed ciphertext size: all writes are exactly MAX_CIPHERTEXT_SIZE bytes.
    Payload length is hidden inside the AEAD envelope.
  - No occupancy metadata: the file contains no slot count, allocation map,
    or any structure visible without a passphrase.
  - AAD address binding: buildAAD includes the derived address, preventing
    an attacker from relocating a ciphertext blob to a different offset.
  - CSPRNG initialisation: the entire file is random bytes at creation.
    Occupied and unoccupied regions are indistinguishable.

Section 10 — Known limitations, add:
  - Collision probability: with default settings (64 MiB file, 64 KiB max
    ciphertext, 8 secrets), the probability of any two secrets colliding is
    approximately 6.25%. Use knownPassphrases in write() and read() to
    enable active collision detection and resolution.
  - Collision detection requires revealing other passphrases to the write()
    call. If this is unacceptable for your threat model, use Tier 1 only
    (accept the ~6% collision probability) or increase totalSize.
  - Retry index in envelope: if Tier 2 collision detection displaced a write
    to a retry address, the read() call must receive the same knownPassphrases
    to locate the secret. If knownPassphrases are lost, the secret is still
    accessible by trying all MAX_COLLISION_RETRIES addresses sequentially.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECURITY REQUIREMENTS (additions to existing list)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

10. DERIVED KEY ZEROING IN deriveAddress
    deriveAddressMaterial returns a 64-byte buffer. The encryptionKey slice
    (bytes 0–31) must be managed via withKey at every call site.
    The full 64-byte material buffer must be zeroed immediately after
    slicing encryptionKey and addressSeed. Use a try/finally for this.

11. NO DOMAIN_SALT IN ERRORS OR LOGS
    DOMAIN_SALT is not secret but must not appear in error messages or logs
    since its exposure combined with other information could aid analysis.

12. FIXED-SIZE READS
    read() always reads exactly MAX_CIPHERTEXT_SIZE bytes from the derived
    address. Never read a variable number of bytes based on any on-disk field,
    since variable-length reads would leak length information.

13. REMOVE FULL SLOT SCAN REQUIREMENT
    The previous requirement to scan all slots is superseded. With derived
    addressing, there are no slots to scan. A read attempt at the derived
    address either succeeds or returns undefined. No scanning loop exists.
    Timing uniformity is achieved by jitter(50, 200) applied unconditionally.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FINAL INSTRUCTIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- Read every existing file before writing any changes.
- Output every modified or created file in full. Never truncate.
  No placeholder comments. Every function body must be complete.
- Deleted files must be explicitly deleted, not left as stubs.
- Do not change deno.json, deno.lock, or any IO backend files.
- All existing conventions are preserved: *.test.ts suffix, jsr:@std/assert,
  BufferHandle in all tests, undefined not null, withKey for key zeroing,
  satisfies ICryptoScheme, DataView for integer encoding, JSDoc on all exports.
- deno lint must pass with zero warnings.
- deno fmt must produce no diffs.
- deno task test must pass with all tests green.
