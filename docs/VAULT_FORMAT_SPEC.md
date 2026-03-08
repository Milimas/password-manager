# VaultC — Vault File Format Specification v1

## File Extension

`.vcf` (VaultC File)

## Design Goals

- Self-describing (magic + version in header)
- Authenticated encryption (tamper detection)
- Forward-compatible (version field for future migrations)
- Atomic writes (no partial vault corruption)

---

## Binary Layout

All integer fields are **little-endian** unless noted otherwise.

```
┌────────────────────────────────────────────────────────────┐
│                    VAULTC FILE v1                          │
├──────────┬──────┬────┬────────────────────────────────────┤
│ Offset   │ Size │ LE │ Field                              │
├──────────┼──────┼────┼────────────────────────────────────┤
│ 0        │  4   │ -  │ Magic: 0x56 0x41 0x55 0x4C        │
│          │      │    │ (ASCII "VAUL", big-endian display) │
├──────────┼──────┼────┼────────────────────────────────────┤
│ 4        │  4   │ ✓  │ Format version: uint32_t           │
│          │      │    │ Current: 0x00000001                │
├──────────┼──────┼────┼────────────────────────────────────┤
│ 8        │  4   │ ✓  │ Flags: uint32_t (reserved: 0x00)  │
├──────────┼──────┼────┼────────────────────────────────────┤
│ 12       │  32  │ -  │ Salt (Argon2id KDF salt)           │
│          │      │    │ Random, generated once at creation │
├──────────┼──────┼────┼────────────────────────────────────┤
│ 44       │  16  │ -  │ Nonce (AES-256-GCM IV)            │
│          │      │    │ Random, regenerated on every save  │
├──────────┼──────┼────┼────────────────────────────────────┤
│ 60       │  4   │ ✓  │ KDF memory cost: uint32_t          │
│          │      │    │ Argon2id mem_limit (bytes)         │
│          │      │    │ Default: 67108864 (64 MiB)         │
├──────────┼──────┼────┼────────────────────────────────────┤
│ 64       │  4   │ ✓  │ KDF ops cost: uint32_t             │
│          │      │    │ Argon2id ops_limit                 │
│          │      │    │ Default: 3                         │
├──────────┼──────┼────┼────────────────────────────────────┤
│ 68       │  8   │ ✓  │ Ciphertext length: uint64_t        │
│          │      │    │ Byte count of the ciphertext below │
├──────────┼──────┼────┼────────────────────────────────────┤
│ 76       │  16  │ -  │ AES-256-GCM authentication tag     │
│          │      │    │ (detached from ciphertext)         │
├──────────┼──────┴────┴────────────────────────────────────┤
│ 92       │  N bytes — Ciphertext                          │
│          │  Encrypted SQLite3 database                    │
│          │  N == value of "Ciphertext length" field       │
└──────────┴────────────────────────────────────────────────┘

Total header size: 92 bytes
Total file size:   92 + N bytes
```

---

## KDF Parameters

| Parameter   | Default Value      | libsodium Constant                       |
|-------------|-------------------|------------------------------------------|
| Algorithm   | Argon2id          | `crypto_pwhash_ALG_ARGON2ID13`          |
| Key length  | 32 bytes          | `crypto_aead_aes256gcm_KEYBYTES` (= 32) |
| ops_limit   | 3                 | `crypto_pwhash_OPSLIMIT_MODERATE`        |
| mem_limit   | 64 MiB            | `crypto_pwhash_MEMLIMIT_MODERATE`        |
| Salt length | 32 bytes          | `crypto_pwhash_SALTBYTES` (= 32)        |

The ops and mem limits are stored in the file header so that future versions
can increase the cost without breaking existing vaults.

---

## Encryption

| Parameter        | Value                                    |
|------------------|------------------------------------------|
| Algorithm        | AES-256-GCM                             |
| Key size         | 32 bytes (256 bits)                      |
| Nonce size       | 16 bytes (96-bit nonce in libsodium API) |
| Tag size         | 16 bytes (128-bit authentication tag)    |
| libsodium API    | `crypto_aead_aes256gcm_encrypt_detached` |
| Additional data  | None (NULL, 0)                           |

**Why detached mode?** Storing the tag separately in the header makes the
format self-describing. The ciphertext length field refers to pure ciphertext
bytes, not ciphertext+tag.

---

## Plaintext Content

The plaintext (after successful decryption) is a complete, valid SQLite3
database file as produced by `sqlite3_serialize()`. It can be opened directly
with any SQLite3 tool for debugging (never do this in production).

Schema version is stored in the `metadata` table:
```sql
SELECT value FROM metadata WHERE key = 'schema_version';
-- Returns '1' for this format version
```

---

## Version Migration Plan

Future format versions will:
1. Increment the `version` field in the header
2. Provide a `vault_migrate_v1_to_v2()` function in vault.c
3. Rewrite the file with the new format after successful migration
4. Be documented in this file under a new section

Current reader behavior on unknown version:
```c
if (header.version > VAULTC_VERSION) {
    log_error("Vault version %u not supported (max: %u)",
              header.version, VAULTC_VERSION);
    return VAULTC_ERR_CORRUPT;
}
```

---

## C Struct Representation

```c
/* include/vaultc/vault_format.h */

#pragma pack(push, 1)   /* Ensure no padding in struct for direct I/O */
typedef struct {
    uint8_t  magic[4];          /* { 0x56, 0x41, 0x55, 0x4C } */
    uint32_t version;           /* 1 */
    uint32_t flags;             /* 0 */
    uint8_t  salt[32];
    uint8_t  nonce[16];
    uint32_t kdf_mem;
    uint32_t kdf_ops;
    uint64_t ciphertext_len;
    uint8_t  tag[16];
    /* Ciphertext follows immediately after this struct */
} VaultFileHeader;
#pragma pack(pop)

/* Compile-time size assertion */
_Static_assert(sizeof(VaultFileHeader) == 92,
               "VaultFileHeader must be exactly 92 bytes");
```

---

## Read Algorithm (Pseudocode)

```
function vault_open(path, master_password):
    f = fopen(path, "rb")

    header = fread(f, sizeof(VaultFileHeader))

    if header.magic != [0x56, 0x41, 0x55, 0x4C]:
        return ERR_CORRUPT

    if header.version != 1:
        return ERR_CORRUPT

    key = Argon2id(
        password = master_password,
        salt     = header.salt,
        ops      = header.kdf_ops,
        mem      = header.kdf_mem,
        keylen   = 32
    )

    ciphertext = fread(f, header.ciphertext_len)
    fclose(f)

    plaintext = AES256GCM_decrypt(
        ciphertext = ciphertext,
        key        = key,
        nonce      = header.nonce,
        tag        = header.tag
    )

    if AES256GCM_tag_invalid:
        sodium_memzero(key)
        return ERR_BAD_PASSWORD

    db = sqlite3_open_memory()
    sqlite3_deserialize(db, plaintext)

    sodium_memzero(key)
    sodium_memzero(plaintext)

    return VaultHandle{ db, ... }
```

---

## Write Algorithm (Pseudocode)

```
function vault_save(handle):
    raw_sqlite = sqlite3_serialize(handle.db)

    nonce = random_bytes(16)   # MUST be fresh every write

    ciphertext, tag = AES256GCM_encrypt_detached(
        plaintext = raw_sqlite,
        key       = handle.key,
        nonce     = nonce
    )

    header = VaultFileHeader{
        magic          = [0x56, 0x41, 0x55, 0x4C],
        version        = 1,
        flags          = 0,
        salt           = handle.salt,   # unchanged from open
        nonce          = nonce,         # fresh
        kdf_mem        = handle.kdf_mem,
        kdf_ops        = handle.kdf_ops,
        ciphertext_len = len(ciphertext),
        tag            = tag,
    }

    tmp_path = handle.path + ".tmp"
    f = fopen(tmp_path, "wb")
    fwrite(f, header)
    fwrite(f, ciphertext)
    fclose(f)

    rename(tmp_path, handle.path)   # atomic on POSIX

    sodium_memzero(raw_sqlite)
    sodium_memzero(ciphertext)

    return OK
```

---

## Security Properties

| Property              | Guarantee                                          |
|-----------------------|----------------------------------------------------|
| Confidentiality       | AES-256-GCM; 256-bit key; computationally secure   |
| Integrity             | GCM authentication tag; any tampering detected     |
| Authenticity          | Tag also covers nonce; nonce substitution detected |
| Password protection   | Argon2id KDF; brute force is very expensive        |
| Nonce freshness       | New random nonce every save; no nonce reuse        |
| Key erasure           | Key zeroed with sodium_memzero after close/lock    |

---

## Test Vectors

For implementation verification, use the following known-good values:

```
Master password:  "correct-horse-battery-staple"
Salt (hex):       000102030405060708090a0b0c0d0e0f
                  101112131415161718191a1b1c1d1e1f
KDF ops:          3
KDF mem:          67108864

Expected key:     [run crypto_pwhash with above inputs and verify
                   output is deterministic across platforms]

Test: derive key on Linux, Windows, and macOS — must be identical.
This verifies Argon2id implementation consistency (libsodium guarantees this).
```
