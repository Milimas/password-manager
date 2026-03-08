# VaultC — AI Agent Implementation Guide

## Purpose

This document tells an AI coding agent the exact order to implement VaultC,
what each task requires, what "done" means, and what to verify before moving on.

Read ARCHITECTURE.md and CODING_STANDARDS.md before writing any code.
Follow CODING_STANDARDS.md for every line written.

---

## Prerequisites (Agent must verify before starting)

- [ ] CMake >= 3.20 available
- [ ] C11 compiler (gcc or clang or MSVC)
- [ ] libsodium development headers installed
- [ ] SQLite3 development headers installed
- [ ] GTK4 development headers installed
- [ ] pkg-config available (Linux/macOS) or vcpkg (Windows)

---

## Implementation Phases

### PHASE 0 — Project Scaffold

**Task 0.1: CMakeLists.txt**

Create the root CMake build file. It must:
- Set `cmake_minimum_required(VERSION 3.20)`
- Set `project(vaultc VERSION 0.1.0 LANGUAGES C)`
- Set `CMAKE_C_STANDARD 11` and `CMAKE_C_STANDARD_REQUIRED ON`
- Find packages: `PkgConfig`, `libsodium`, `SQLite3`, `GTK4`
- Add subdirectories: `src`, `tests`
- Define compiler flags: `-Wall -Wextra -Wpedantic` (Debug: add `-fsanitize=address,undefined`)
- Create `src/CMakeLists.txt` that builds all .c files into a library + executable

Done when: `cmake -B build && cmake --build build` succeeds with no warnings.

**Task 0.2: Create all empty source files**

Create every `.c` and `.h` file listed in the file tree in `DIAGRAMS.md`.
Each `.c` file gets a comment header:
```c
/*
 * VaultC — <module description>
 * File: src/<path>/<filename>.c
 */
```
Each `.h` file gets its include guard and `extern "C"` wrapper.

Done when: All files exist and the project still compiles (empty stubs).

**Task 0.3: types.h — shared type definitions**

Populate `include/vaultc/types.h` with:
- `VaultcError` enum (all error codes from ARCHITECTURE.md)
- `ImportFormat` enum: `IMPORT_UNKNOWN, IMPORT_GOOGLE, IMPORT_FIREFOX, IMPORT_IOS, IMPORT_BITWARDEN, IMPORT_LASTPASS, IMPORT_GENERIC`
- `StrengthScore` enum: `STRENGTH_VERY_WEAK, STRENGTH_WEAK, STRENGTH_FAIR, STRENGTH_STRONG, STRENGTH_VERY_STRONG`
- `Entry` struct (all fields from SQLite schema in ARCHITECTURE.md)
- `EntryList` struct
- `ImportResult` struct
- `PwgenOptions` struct

Done when: All other headers can `#include "vaultc/types.h"` without errors.

---

### PHASE 1 — Crypto Layer

**Task 1.1: crypto.h — declarations**

Declare all functions listed in the "crypto.c" section of ARCHITECTURE.md.
Add `VaultcError` return types and full Doxygen comments for each.

**Task 1.2: crypto.c — implementation**

Implement each function:

```
crypto_init()
  → call sodium_init(), return VAULTC_ERR_CRYPTO if it returns -1

crypto_derive_key(password, salt, ops, mem, key_out)
  → crypto_pwhash(key_out, KEY_BYTES, password, strlen(password),
                  salt, ops, mem, crypto_pwhash_ALG_ARGON2ID13)
  → map libsodium errors to VaultcError

crypto_encrypt(plaintext, len, key, nonce, ciphertext_out, tag_out)
  → crypto_aead_aes256gcm_encrypt_detached(...)

crypto_decrypt(ciphertext, len, key, nonce, tag, plaintext_out)
  → crypto_aead_aes256gcm_decrypt_detached(...)
  → return VAULTC_ERR_BAD_PASSWORD if tag verify fails

crypto_random_bytes(buf, len)
  → randombytes_buf(buf, len)

crypto_secure_zero(buf, len)
  → sodium_memzero(buf, len)
```

**Task 1.3: test_crypto.c**

Write tests for:
- `crypto_init()` succeeds
- `crypto_derive_key()` is deterministic (same inputs → same key)
- `crypto_derive_key()` avalanche (1-char password change → completely different key)
- `crypto_encrypt()` → `crypto_decrypt()` round-trips correctly
- `crypto_decrypt()` with wrong key returns `VAULTC_ERR_BAD_PASSWORD`
- `crypto_decrypt()` with tampered ciphertext returns `VAULTC_ERR_BAD_PASSWORD`
- `crypto_random_bytes()` produces non-zero output

Done when: `ctest -R test_crypto` passes all tests.

---

### PHASE 2 — Vault Format I/O

**Task 2.1: vault.h + vault.c skeleton**

Define `struct VaultHandle` (private, in vault.c only).
Declare all public functions in vault.h.

**Task 2.2: vault_create()**

```
vault_create(path, master_password):
  1. calloc(1, sizeof(VaultHandle))
  2. crypto_random_bytes(salt, 32)
  3. crypto_derive_key(master_password, salt, DEFAULT_OPS, DEFAULT_MEM, key)
  4. Open SQLite in-memory: sqlite3_open(":memory:", &db)
  5. Run schema SQL (see ARCHITECTURE.md schema — all CREATE TABLE statements)
  6. Insert metadata rows: vault_name="My Vault", schema_version="1"
  7. vault_save() to write encrypted file
  8. Return VaultHandle* or NULL on error (goto cleanup pattern)
```

**Task 2.3: vault_open()**

```
vault_open(path, master_password):
  1. fopen(path, "rb")
  2. Read and validate header (magic, version)
  3. If magic != VAULTC_MAGIC: return NULL (VAULTC_ERR_CORRUPT)
  4. crypto_derive_key(master_password, header.salt, ops, mem, key)
  5. Read ciphertext bytes
  6. crypto_decrypt(ciphertext, key, nonce, tag, plaintext)
  7. If decrypt fails: return NULL (VAULTC_ERR_BAD_PASSWORD)
  8. sqlite3_open(":memory:", &db)
  9. sqlite3_deserialize(db, plaintext, len, ...)
  10. Return populated VaultHandle*
```

**Task 2.4: vault_save()**

```
vault_save(handle):
  1. sqlite3_serialize(handle->db, ...) → raw_bytes, raw_len
  2. crypto_random_bytes(nonce, 16)  ← fresh nonce every save
  3. crypto_encrypt(raw_bytes, raw_len, handle->key, nonce, ciphertext, tag)
  4. Build header struct (fill all fields)
  5. Write to <path>.tmp using fwrite (header then ciphertext)
  6. fclose, then rename(<path>.tmp, <path>)  ← atomic
  7. sodium_memzero(raw_bytes, raw_len); free(raw_bytes)
  8. Return VAULTC_OK or error code
```

**Task 2.5: vault_close()**

```
vault_close(handle):
  1. sqlite3_close(handle->db)
  2. sodium_memzero(handle->key, sizeof(handle->key))
  3. free(handle->path)
  4. free(handle)
```

**Task 2.6: test_vault.c**

Test:
- `vault_create()` produces a file with correct magic bytes
- `vault_open(correct_password)` succeeds
- `vault_open(wrong_password)` returns NULL
- `vault_open()` on truncated file returns NULL (CORRUPT)
- `vault_save()` + `vault_open()` round-trip: metadata survives
- After `vault_close()`, key memory is zeroed (check with valgrind)

Done when: `ctest -R test_vault` passes.

---

### PHASE 3 — Database CRUD Layer

**Task 3.1: db.h + db.c**

Implement all functions from the "db.c" section of ARCHITECTURE.md.

Key implementation notes:
- All INSERT statements use prepared statements (never string interpolation)
- `db_entry_list()` accepts a nullable filter string (SQL LIKE on title/url/username)
- `db_free_entry()` MUST call `sodium_memzero` on `entry->password` and `entry->totp_secret` before free
- Use `db_audit_log()` internal function called by create/update/delete

SQL for search:
```sql
SELECT * FROM entries
WHERE title LIKE ?1 OR url LIKE ?1 OR username LIKE ?1
ORDER BY updated_at DESC;
```

**Task 3.2: test_db.c**

Test:
- Create entry → read back → fields match
- Update entry → read back → fields updated, updated_at changed
- Delete entry → read returns NULL
- List entries with no filter → returns all
- Search "goo" matches "Google" in title
- Duplicate UUID rejected
- `db_free_entry` zeroes password field (test with known pattern)

---

### PHASE 4 — Utilities

**Task 4.1: uuid.c** — UUID v4 using `randombytes_buf` for entropy. Format: `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`.

**Task 4.2: csv_parser.c** — RFC 4180 compliant. Handle:
- Quoted fields (fields may contain commas inside quotes)
- Escaped quotes (`""` inside quoted field = literal `"`)
- CRLF and LF line endings
- UTF-8 content passthrough

API:
```c
CsvParser *csv_open(const char *path);
int        csv_read_row(CsvParser *p, char ***fields_out, int *count_out);
void       csv_close(CsvParser *p);
```

**Task 4.3: totp.c** — RFC 6238 TOTP implementation.
- Base32 decode the secret
- HMAC-SHA1 using libsodium's `crypto_auth_hmacsha1`
- Standard 30-second window, 6-digit code
- `totp_generate(base32_secret)` → char[7]

**Task 4.4: clipboard.c**
```c
void clipboard_set_text(GtkWidget *widget, const char *text);
void clipboard_schedule_clear(int seconds);  /* clears after timeout */
void clipboard_clear_now(void);
```
Use `gdk_clipboard_set_text()` and `g_timeout_add_seconds()`.

---

### PHASE 5 — Import Engine

**Task 5.1: importer.c — format detection**

Column signature matching:
```
Google CSV headers:   "name","url","username","password","note"
Firefox CSV headers:  "url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"
iOS CSV headers:      "Title","URL","Username","Password","Notes","OTPAuth"
Bitwarden CSV headers:"folder","favorite","type","name","notes","fields","reprompt","login_uri","login_username","login_password","login_totp"
```

`import_detect_format()` reads only the first line (header row) and returns the best match.

**Task 5.2: import_google.c**

Field mapping:
```
name     → entry.title
url      → entry.url
username → entry.username
password → entry.password
note     → entry.notes
```
Set `entry.source = "google"`.
Detect duplicates: if an entry with same URL + username already exists, skip and increment `result.skipped_duplicates`.

**Task 5.3: import_firefox.c**

Field mapping:
```
url      → entry.url
username → entry.username
password → entry.password
```
Derive title from hostname: `"Firefox Import — example.com"`.
Set `entry.source = "firefox"`.

**Task 5.4: import_ios.c**

Field mapping:
```
Title    → entry.title
URL      → entry.url
Username → entry.username
Password → entry.password
Notes    → entry.notes
OTPAuth  → entry.totp_secret (extract secret from otpauth:// URI)
```
Set `entry.source = "ios"`.

**Task 5.5: import_bitwarden.c**

Only import `type == "login"` rows (skip cards, identities, etc.).
Field mapping:
```
name           → entry.title
login_uri      → entry.url
login_username → entry.username
login_password → entry.password
notes          → entry.notes
login_totp     → entry.totp_secret
folder         → entry.category
```

**Task 5.6: test_import.c**

Use sample CSV files in `tests/fixtures/`:
- `google_sample.csv` — 3 entries including one with commas in URL
- `firefox_sample.csv` — 3 entries
- `ios_sample.csv` — 2 entries, one with OTPAuth
- `bitwarden_sample.csv` — 4 entries, one is a card (should be skipped)

Tests:
- Format detection returns correct enum for each file
- Import counts match expected (imported + skipped)
- Fields mapped correctly (spot check title, url, username, password)
- Duplicate detection works (run import twice → second run: 0 imported, N skipped)

---

### PHASE 6 — Password Generator

**Task 6.1: pwgen.c**

```c
char *pwgen_generate(const PwgenOptions *opts):
  1. Build charset from enabled character classes
  2. Loop until password meets minimum requirements:
     a. Fill buffer with crypto_random_bytes
     b. Map each byte to charset using modulo (if charset fits in power of 2, use rejection sampling for uniformity)
  3. Shuffle result using Fisher-Yates with randombytes_buf indices
  4. Return heap-allocated string (caller must free + sodium_memzero)

double pwgen_entropy_bits(const char *password):
  → Estimate charset size from character analysis
  → entropy = log2(charset_size) * strlen(password)

StrengthScore pwgen_check_strength(const char *password):
  → Map entropy_bits to StrengthScore thresholds:
     < 28  → VERY_WEAK
     28-35 → WEAK
     36-59 → FAIR
     60-127→ STRONG
     128+  → VERY_STRONG
```

**Task 6.2: test_pwgen.c**

- Generated password length matches `opts.length`
- With only digits enabled: output contains only `[0-9]`
- With all classes: output contains at least one of each class
- Entropy function returns plausible values
- Generating 1000 passwords: no two are identical (birthday check)

---

### PHASE 7 — GTK4 UI

Read GTK4 documentation pattern. All UI code uses GtkBuilder or hand-coded widgets (no .ui XML files to keep everything in C).

**Task 7.1: ui_app.c — GtkApplication**

```c
int main(int argc, char **argv):
  GtkApplication *app = gtk_application_new("com.vaultc.app", G_APPLICATION_DEFAULT_FLAGS);
  g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
  return g_application_run(G_APPLICATION(app), argc, argv);

static void on_activate(GtkApplication *app):
  → Check for vault file in g_get_user_data_dir()/vaultc/vault.vcf
  → If exists: show UnlockDialog
  → If not: show WelcomeDialog (create new vault)
```

**Task 7.2: ui_unlock_dialog.c**

Widgets:
- `GtkWindow` (modal, 400px wide)
- `GtkLabel` — "Enter master password"
- `GtkPasswordEntry` — password input (visibility off by default)
- `GtkButton` — "Unlock" (activates on Enter)
- `GtkLabel` — error label (hidden until wrong password)
- `GtkSpinner` — shown while Argon2id is computing

Behavior:
- Unlock runs in thread via `GTask` (MUST NOT block GTK main loop)
- Wrong password: show error label, re-enable input
- Success: destroy dialog, open `MainWindow`

**Task 7.3: ui_main_window.c**

Layout:
```
┌─────────────────────────────────────┐
│ [🔒 Lock] [+ Add] [⚙ Settings]  VaultC │  ← HeaderBar
├──────────────────┬──────────────────┤
│ 🔍 Search...     │                  │  ← Search entry
├──────────────────┤  Entry Detail    │
│ 📁 All           │  Panel           │
│ ⭐ Favorites     │  (right side)    │
│ 📁 Social        │                  │
│ 📁 Work          │                  │
├──────────────────┤                  │
│ Entry List       │                  │
│ (GtkListBox)     │                  │
└──────────────────┴──────────────────┘
```

Entry list rows show: favicon placeholder + title + username + "Copy Password" button.
Search filters list in real-time using `gtk_list_box_set_filter_func`.
Auto-lock: `g_timeout_add_seconds(300, on_autolock_timeout, window)`.

**Task 7.4: ui_entry_dialog.c**

Fields: Title*, URL, Username, Password (toggle visibility), Notes (multiline), Category, Favorite toggle, TOTP secret.
Password field has "Generate" button that opens `GeneratorDialog` and pastes result.
"Save" calls `session_save_entry()`, closes on VAULTC_OK.

**Task 7.5: ui_import_dialog.c**

Steps:
1. File chooser (GtkFileDialog) — filter for *.csv
2. Auto-detect format, show detected label
3. Preview table (GtkColumnView) showing first 5 rows
4. "Import" button → progress bar → ImportResult summary

**Task 7.6: ui_generator_dialog.c**

- `GtkScale` — length (8–64)
- `GtkCheckButton` × 4 — uppercase, lowercase, digits, symbols
- `GtkEntry` — exclude characters
- `GtkLabel` — generated password (large font)
- `GtkLevelBar` — strength meter
- "Regenerate" button, "Copy & Close" button

**Task 7.7: ui_settings_dialog.c**

Settings:
- Auto-lock timeout (GtkDropDown: 1/5/15/30 min / never)
- Clipboard clear delay (GtkSpinButton: 10–120 seconds)
- Default password length
- "Change master password" button → triggers vault_change_password()
- "Export vault" button (export decrypted CSV — warn user)

---

### PHASE 8 — Integration & Polish

**Task 8.1: session.c — application state**

```c
typedef struct {
    VaultHandle *vault;
    char        *vault_path;
    int          is_locked;
    GTimer      *last_activity;
} AppSession;
```

Single global `AppSession g_session`.  
Provides the bridge between UI and vault/db/import layers.  
All UI code calls session functions, never vault/db directly.

**Task 8.2: Final integration testing**

Manual test checklist:
- [ ] Create new vault, add 3 entries, close app, reopen — entries present
- [ ] Wrong master password shows error and doesn't open vault
- [ ] Import Google CSV, verify entry count in list
- [ ] Import same CSV again, verify duplicates skipped
- [ ] Copy password → clipboard has password → after 30s clipboard is cleared
- [ ] Generator produces passwords of correct length and character classes
- [ ] Lock button locks vault, password required to re-enter
- [ ] Auto-lock fires after configured timeout

**Task 8.3: CMake install target**

```cmake
install(TARGETS vaultc DESTINATION bin)
install(FILES com.vaultc.app.desktop DESTINATION share/applications)
```

Create `com.vaultc.app.desktop` file for Linux application menu integration.

---

## Coding Checklist (run before marking any task done)

- [ ] No compiler warnings with `-Wall -Wextra -Wpedantic`
- [ ] All sensitive buffers zeroed with `sodium_memzero` before free
- [ ] All `malloc`/`calloc` return values checked
- [ ] All file handles and DB connections closed in error paths (goto cleanup)
- [ ] No use of forbidden functions (see CODING_STANDARDS.md §12)
- [ ] New functions have Doxygen comments in the `.h` file
- [ ] Any new public function has at least one test case

---

## Dependency Versions (Minimum)

| Library    | Minimum Version | Notes                          |
|------------|-----------------|--------------------------------|
| libsodium  | 1.0.18          | Stable AES-GCM API             |
| SQLite3    | 3.37.0          | sqlite3_serialize available    |
| GTK        | 4.6.0           | GtkFileDialog available in 4.10|
| GLib       | 2.72            | GTask, GApplication            |
| CMake      | 3.20            | find_package improvements      |

---

## Windows-Specific Notes

- Use MSYS2 + MinGW-w64 or vcpkg for dependencies
- GTK4 on Windows: install via `winget install MSYS2` then `pacman -S mingw-w64-x86_64-gtk4`
- libsodium Windows: prebuilt binaries available at libsodium.org
- Replace `rename()` with `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)` — handled via GLib `g_rename()`
- Icon: create `vaultc.ico` and reference in `vaultc.rc`

## macOS-Specific Notes

- GTK4 on macOS: `brew install gtk4`
- libsodium: `brew install libsodium`
- App bundle: use CPack to generate `.app` bundle in CMake
- Code signing: requires Apple Developer account for distribution
