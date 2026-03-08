# VaultC — System Architecture

## Overview

VaultC is a personal, local-first password manager written in C, targeting Windows,
Linux, and macOS. It uses GTK4 for the GUI, libsodium for all cryptographic operations,
and SQLite as the internal database, stored inside a single encrypted vault file.

---

## Guiding Principles

1. **Security first** — sensitive memory is always zeroed after use (`sodium_memzero`).
2. **No network** — the vault never phones home. All operations are local.
3. **Single vault file** — one `.vcf` file holds everything; easy to back up.
4. **Minimal dependencies** — GTK4, libsodium, SQLite3. Nothing else.
5. **Cross-platform from day one** — no platform-specific APIs in core logic.
6. **Layered architecture** — UI knows nothing about crypto; core knows nothing about UI.

---

## High-Level Layer Diagram

```
┌─────────────────────────────────────────────────┐
│                   UI Layer (GTK4)                │
│  Windows / Dialogs / Widgets / Clipboard mgmt   │
└───────────────────────┬─────────────────────────┘
                        │ calls
┌───────────────────────▼─────────────────────────┐
│                Application Layer                 │
│   Session state, lock/unlock, search, TOTP      │
└──────┬──────────────┬──────────────┬────────────┘
       │              │              │
┌──────▼─────┐ ┌──────▼──────┐ ┌───▼────────────┐
│ Vault Core │ │Import Engine│ │ PwGen Module   │
│ CRUD + I/O │ │ CSV parsers │ │ Entropy + rules│
└──────┬─────┘ └─────────────┘ └────────────────┘
       │
┌──────▼─────────────────────────────────────────┐
│               Crypto Layer (libsodium)          │
│   KDF (Argon2id) · AES-256-GCM · Secure mem   │
└──────┬─────────────────────────────────────────┘
       │
┌──────▼─────────────────────────────────────────┐
│            Storage Layer (SQLite3)             │
│   Embedded DB, serialized, encrypted at rest   │
└────────────────────────────────────────────────┘
```

---

## Vault File Format (.vcf)

The vault is a single binary file with the following layout:

```
Offset  Size   Field
------  ----   -----
0       4      Magic: 0x56 0x41 0x55 0x4C ("VAUL")
4       4      Version: uint32_t little-endian (current: 1)
8       4      Flags: uint32_t (reserved, set to 0)
12      32     Salt (random, generated at vault creation)
44      16     Nonce (random, regenerated on every save)
60      4      KDF memory cost (Argon2id mem_limit, uint32_t)
64      4      KDF ops cost (Argon2id ops_limit, uint32_t)
68      8      Ciphertext length (uint64_t little-endian)
76      16     GCM authentication tag
92      N      Ciphertext (encrypted SQLite3 database bytes)
```

**Decryption flow:**
1. Read salt + nonce + costs from header.
2. Derive 32-byte key: `Argon2id(master_password, salt, ops, mem)`.
3. Decrypt ciphertext with `AES-256-GCM(key, nonce, ciphertext, tag)`.
4. Verify GCM tag — reject if invalid (wrong password or corruption).
5. Open decrypted bytes as in-memory SQLite database.

**Encryption flow (on save):**
1. Serialize in-memory SQLite DB to bytes.
2. Generate fresh random nonce.
3. Encrypt with `AES-256-GCM`.
4. Write full header + ciphertext to disk (atomic write via temp file + rename).

---

## Internal SQLite Schema

```sql
-- Core password entries
CREATE TABLE entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid        TEXT NOT NULL UNIQUE,           -- RFC-4122 UUID
    title       TEXT NOT NULL,
    url         TEXT,
    username    TEXT,
    password    TEXT NOT NULL,                  -- plaintext inside encrypted DB
    notes       TEXT,
    totp_secret TEXT,                           -- base32 TOTP seed (optional)
    category    TEXT DEFAULT 'General',
    is_favorite INTEGER DEFAULT 0,
    created_at  INTEGER NOT NULL,               -- Unix timestamp
    updated_at  INTEGER NOT NULL,
    last_used   INTEGER,
    source      TEXT DEFAULT 'manual'           -- 'manual','google','firefox','ios', etc.
);

-- Tags (many-to-many)
CREATE TABLE tags (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE entry_tags (
    entry_id INTEGER REFERENCES entries(id) ON DELETE CASCADE,
    tag_id   INTEGER REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (entry_id, tag_id)
);

-- Audit log (never leaves the vault)
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_uuid TEXT,
    action     TEXT NOT NULL,  -- 'create','update','delete','view','copy'
    timestamp  INTEGER NOT NULL
);

-- Vault metadata
CREATE TABLE metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- metadata rows: 'vault_name', 'created_at', 'schema_version', 'last_import'
```

---

## Module Responsibilities

### `core/crypto.c` — Crypto Layer
- `crypto_init()` — initialize libsodium
- `crypto_derive_key(password, salt, ops, mem, key_out)` — Argon2id KDF
- `crypto_encrypt(plaintext, len, key, nonce, ciphertext_out, tag_out)`
- `crypto_decrypt(ciphertext, len, key, nonce, tag, plaintext_out)`
- `crypto_random_bytes(buf, len)` — wrapper for `randombytes_buf`
- `crypto_secure_zero(buf, len)` — wrapper for `sodium_memzero`

### `core/vault.c` — Vault I/O
- `vault_create(path, master_password)` → VaultHandle*
- `vault_open(path, master_password)` → VaultHandle* or NULL on auth fail
- `vault_save(VaultHandle*)` → int (0=ok, <0=error)
- `vault_close(VaultHandle*)` — zeroes key material, closes DB
- `vault_change_password(VaultHandle*, old_pw, new_pw)`

### `core/db.c` — Database Operations
- `db_entry_create(db, Entry*)` → int
- `db_entry_read(db, uuid)` → Entry*
- `db_entry_update(db, Entry*)` → int
- `db_entry_delete(db, uuid)` → int
- `db_entry_list(db, filter)` → EntryList*
- `db_entry_search(db, query)` → EntryList*
- `db_free_entry(Entry*)`
- `db_free_entry_list(EntryList*)`

### `import/importer.c` — Import Engine
- `import_detect_format(csv_path)` → ImportFormat enum
- `import_google_csv(db, path)` → ImportResult
- `import_firefox_csv(db, path)` → ImportResult
- `import_ios_csv(db, path)` → ImportResult
- `import_bitwarden_csv(db, path)` → ImportResult
- `import_generic_csv(db, path, FieldMap*)` → ImportResult

### `generator/pwgen.c` — Password Generator
- `pwgen_generate(PwgenOptions*)` → char* (caller frees)
- `pwgen_entropy_bits(password)` → double
- `pwgen_check_strength(password)` → StrengthScore

### `ui/` — GTK4 UI (one file per window/dialog)
- `ui_main_window.c` — main list view, search bar, toolbar
- `ui_unlock_dialog.c` — master password prompt
- `ui_entry_dialog.c` — add/edit entry form
- `ui_import_dialog.c` — file picker + format selector + preview
- `ui_generator_dialog.c` — password generator widget
- `ui_settings_dialog.c` — vault settings, auto-lock timeout
- `ui_app.c` — GtkApplication setup, signal wiring

### `utils/`
- `utils_clipboard.c` — set clipboard, schedule auto-clear
- `utils_uuid.c` — UUID v4 generation
- `utils_totp.c` — TOTP code generation (RFC 6238)
- `utils_csv.c` — RFC 4180-compliant CSV parser

---

## Cross-Platform Strategy

| Concern            | Solution                                      |
|--------------------|-----------------------------------------------|
| GUI                | GTK4 (native on Linux, works on Win/Mac)      |
| Build system       | CMake 3.20+ with platform detection           |
| File paths         | Always use `g_build_filename()` (GLib)        |
| Secure memory lock | `sodium_mlock()` with fallback if unavailable |
| Config directory   | `g_get_user_data_dir()` (GLib, cross-platform)|
| Clipboard clear    | GDK clipboard API (abstracted by GTK)         |
| Atomic file write  | temp file + `g_rename()` (GLib wrapper)       |

---

## Security Threat Model

| Threat                        | Mitigation                                      |
|-------------------------------|-------------------------------------------------|
| Vault file stolen             | AES-256-GCM encryption; useless without key     |
| Weak master password          | Argon2id with high cost parameters              |
| Key in memory after lock      | `sodium_memzero` on lock/close                  |
| Clipboard snooping            | Auto-clear clipboard after 30 seconds           |
| Screen capture of passwords   | Password fields use GTK's `set_visibility(FALSE)`|
| Swap/pagefile exposure        | `sodium_mlock()` to prevent paging              |
| Backup of plaintext DB        | Only encrypted .vcf file is ever written        |
| Import file left on disk      | User responsibility; import dialog warns        |
| Brute force                   | Argon2id cost makes offline attack expensive    |
