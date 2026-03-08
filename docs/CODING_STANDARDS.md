# VaultC — C Coding Standards

## Philosophy

VaultC is a security-sensitive application. Every line of code must be written with
clarity, correctness, and safety in mind. When in doubt: simpler is safer.

---

## 1. Language Standard

- **Target:** C11 (`-std=c11`)
- **Warnings:** Always compile with `-Wall -Wextra -Wpedantic -Werror`
- **Sanitizers:** Use `-fsanitize=address,undefined` in Debug builds
- No C++ extensions. No GNU extensions unless wrapped in `#ifdef` guards.

---

## 2. File Organization

### Header Files (`.h`)
```c
/* vaultc/include/vaultc/vault.h */

#ifndef VAULTC_VAULT_H   /* Include guard — always use full path style */
#define VAULTC_VAULT_H

#include <stdint.h>      /* System includes first */
#include <stddef.h>

#include "vaultc/types.h"  /* Project includes second */

#ifdef __cplusplus       /* C++ compatibility guard at bottom of header */
extern "C" {
#endif

/* --- Type Definitions --- */

typedef struct VaultHandle VaultHandle;  /* Opaque type — impl in .c file */

/* --- Constants --- */

#define VAULTC_MAGIC        0x4C554156U  /* "VAUL" little-endian */
#define VAULTC_VERSION      1U
#define VAULTC_KEY_BYTES    32
#define VAULTC_NONCE_BYTES  16
#define VAULTC_SALT_BYTES   32
#define VAULTC_TAG_BYTES    16

/* --- Error Codes --- */

typedef enum {
    VAULTC_OK               =  0,
    VAULTC_ERR_IO           = -1,
    VAULTC_ERR_CRYPTO       = -2,
    VAULTC_ERR_BAD_PASSWORD = -3,
    VAULTC_ERR_CORRUPT      = -4,
    VAULTC_ERR_NOMEM        = -5,
    VAULTC_ERR_INVALID_ARG  = -6,
} VaultcError;

/* --- Function Declarations --- */

/**
 * Open an existing vault file.
 *
 * @param path            Path to the .vcf vault file.
 * @param master_password Null-terminated master password string.
 * @return                Pointer to VaultHandle on success, NULL on failure.
 *                        Caller must call vault_close() when done.
 */
VaultHandle *vault_open(const char *path, const char *master_password);

/**
 * Save the vault back to disk (atomic write).
 *
 * @param handle  Open vault handle.
 * @return        VAULTC_OK on success, negative error code on failure.
 */
VaultcError vault_save(VaultHandle *handle);

/**
 * Lock and close the vault, zeroing all key material.
 *
 * @param handle  Vault handle to close. Pointer is invalid after this call.
 */
void vault_close(VaultHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* VAULTC_VAULT_H */
```

### Source Files (`.c`)
```c
/* src/core/vault.c */

/* Project header for this module FIRST */
#include "vaultc/vault.h"

/* Then system headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Then third-party headers */
#include <sodium.h>
#include <sqlite3.h>

/* Then other project headers */
#include "vaultc/crypto.h"
#include "vaultc/db.h"

/* --- Private struct definition (opaque outside this file) --- */

struct VaultHandle {
    sqlite3    *db;
    uint8_t     key[VAULTC_KEY_BYTES];   /* MUST be zeroed on close */
    uint8_t     salt[VAULTC_SALT_BYTES];
    char       *path;
    uint32_t    kdf_ops;
    uint32_t    kdf_mem;
    int         is_modified;
};
```

---

## 3. Naming Conventions

| Entity            | Convention              | Example                        |
|-------------------|-------------------------|--------------------------------|
| Functions         | `module_verb_noun`      | `vault_open`, `db_entry_read`  |
| Types (structs)   | `PascalCase`            | `VaultHandle`, `Entry`         |
| Enum types        | `PascalCase`            | `VaultcError`, `ImportFormat`  |
| Enum values       | `UPPER_SNAKE_CASE`      | `VAULTC_OK`, `IMPORT_GOOGLE`   |
| Constants/macros  | `UPPER_SNAKE_CASE`      | `VAULTC_KEY_BYTES`             |
| Local variables   | `lower_snake_case`      | `entry_count`, `file_path`     |
| Private functions | `static` + same style   | `static int parse_header(...)`  |
| Boolean-like ints | `is_` or `has_` prefix  | `is_modified`, `has_totp`      |

---

## 4. Memory Management Rules

### Rule 1: Every allocation has a paired free
```c
/* GOOD */
char *buf = malloc(size);
if (buf == NULL) { return VAULTC_ERR_NOMEM; }
/* ... use buf ... */
free(buf);
buf = NULL;   /* Always NULL the pointer after free */
```

### Rule 2: Sensitive buffers MUST be zeroed before free
```c
/* GOOD — for any buffer holding a password, key, or secret */
uint8_t key[32];
crypto_derive_key(password, salt, key);
/* ... use key ... */
sodium_memzero(key, sizeof(key));   /* NOT memset — compiler won't optimize this away */
```

### Rule 3: Check every malloc/calloc return
```c
/* GOOD */
Entry *entry = calloc(1, sizeof(Entry));
if (entry == NULL) {
    log_error("Failed to allocate Entry");
    return VAULTC_ERR_NOMEM;
}
```

### Rule 4: Ownership must be documented
```c
/**
 * Returns a newly allocated Entry. Caller owns it and MUST call db_free_entry().
 */
Entry *db_entry_read(sqlite3 *db, const char *uuid);

/**
 * Frees an Entry previously returned by db_entry_read().
 * Zeroes sensitive fields (password, totp_secret) before freeing.
 */
void db_free_entry(Entry *entry);
```

### Rule 5: Use `strdup` wrappers that check NULL
```c
/* utils/safe_str.h */
static inline char *safe_strdup(const char *s) {
    if (s == NULL) return NULL;
    char *copy = strdup(s);
    if (copy == NULL) { abort(); }  /* OOM is unrecoverable in this app */
    return copy;
}
```

---

## 5. Error Handling

### Always check return values
```c
/* GOOD */
VaultcError err = vault_save(handle);
if (err != VAULTC_OK) {
    ui_show_error_dialog("Failed to save vault: %s", vaultc_strerror(err));
    return;
}
```

### Use goto for cleanup in functions with multiple resources
```c
/* GOOD — single exit point with cleanup */
VaultHandle *vault_open(const char *path, const char *master_password) {
    VaultHandle *handle = NULL;
    uint8_t     *raw_db = NULL;
    FILE        *f      = NULL;

    handle = calloc(1, sizeof(VaultHandle));
    if (handle == NULL) goto fail;

    f = fopen(path, "rb");
    if (f == NULL) goto fail;

    /* ... read and decrypt ... */

    fclose(f);
    return handle;

fail:
    if (f)      fclose(f);
    if (raw_db) { sodium_memzero(raw_db, raw_db_size); free(raw_db); }
    if (handle) { sodium_memzero(handle->key, sizeof(handle->key)); free(handle); }
    return NULL;
}
```

### Never swallow errors silently
```c
/* BAD */
vault_save(handle);

/* GOOD */
if (vault_save(handle) != VAULTC_OK) {
    /* at minimum, log it */
    log_warn("vault_save failed — changes may be lost");
}
```

---

## 6. String Safety

```c
/* NEVER use: strcpy, strcat, sprintf, gets */
/* ALWAYS use: */
snprintf(buf, sizeof(buf), "format", ...);
strnlen(str, max_len);
/* Or GLib equivalents: g_snprintf, g_strndup */

/* For paths, always use GLib: */
char *full_path = g_build_filename(dir, "vault.vcf", NULL);
/* ... use full_path ... */
g_free(full_path);
```

---

## 7. Function Length & Complexity

- **Hard limit: 80 lines per function.** If longer, break into helpers.
- **Max nesting depth: 4 levels.** Use early returns to reduce nesting.
- **Max function parameters: 6.** Beyond that, use a struct.

```c
/* BAD — too many params */
int import_csv(const char *path, sqlite3 *db, int skip_dupes,
               int overwrite, const char *category, int dry_run,
               ImportResult *result, int verbose);

/* GOOD — use an options struct */
typedef struct {
    const char   *path;
    const char   *default_category;
    int           skip_duplicates;
    int           overwrite_existing;
    int           dry_run;
    int           verbose;
} ImportOptions;

int import_csv(sqlite3 *db, const ImportOptions *opts, ImportResult *result);
```

---

## 8. Comments & Documentation

```c
/* Single-line comments use C89 style: /* like this */ */
// C99 // style is also acceptable for single lines

/**
 * Doxygen-style for all public API functions (in headers).
 *
 * @param  name   Description of parameter.
 * @return        What is returned, and when NULL/error is returned.
 *
 * @note   Any important behavioral notes go here.
 * @warning If there's a security/memory concern, note it here.
 */

/* Within function bodies, explain WHY not WHAT: */

/* BAD: increment i */
i++;

/* GOOD: skip the header row which is always present in Google CSV exports */
i++;
```

---

## 9. Preprocessor & Portability

```c
/* Platform detection — use these macros consistently */
#if defined(_WIN32) || defined(_WIN64)
    #define VAULTC_PLATFORM_WINDOWS 1
#elif defined(__APPLE__)
    #define VAULTC_PLATFORM_MACOS 1
#elif defined(__linux__)
    #define VAULTC_PLATFORM_LINUX 1
#else
    #error "Unsupported platform"
#endif

/* Integer types — always use stdint.h, never raw int for binary I/O */
uint32_t version;    /* NOT: unsigned int version; */
int64_t  timestamp;  /* NOT: long timestamp; */

/* Endianness — always write little-endian to disk */
#include "vaultc/endian.h"  /* provides le32_write(), le32_read(), etc. */
```

---

## 10. GTK4 UI Rules

- All UI code lives in `src/ui/`. Core code must NOT include any GTK headers.
- UI callbacks are named `on_<widget>_<signal>`: e.g., `on_save_button_clicked`.
- Never block the GTK main loop. Use `GTask` for any vault I/O from UI.
- Sensitive GTK entry widgets: always call `gtk_entry_set_visibility(entry, FALSE)`.
- Always disconnect signals and unref objects you own when destroying widgets.

```c
/* GOOD — async vault open from UI */
static void on_unlock_button_clicked(GtkButton *btn, gpointer user_data) {
    UnlockDialog *dialog = user_data;
    const char   *pw     = gtk_editable_get_text(GTK_EDITABLE(dialog->pw_entry));

    GTask *task = g_task_new(dialog, NULL, on_vault_open_done, dialog);
    g_task_set_task_data(task, g_strdup(pw), g_free);
    g_task_run_in_thread(task, vault_open_thread_func);
    g_object_unref(task);

    gtk_widget_set_sensitive(GTK_WIDGET(btn), FALSE);  /* prevent double-click */
}
```

---

## 11. Build & Test Requirements

- Every public function in `core/` and `import/` MUST have at least one unit test.
- Tests live in `tests/` and are named `test_<module>.c`.
- Use the included minimal test harness (`tests/harness.h`) — no external test framework.
- CI must pass: `cmake --build . && ctest --output-on-failure`

---

## 12. Forbidden Patterns

| Forbidden                        | Reason                                    | Use Instead                    |
|----------------------------------|-------------------------------------------|--------------------------------|
| `memset` for zeroing secrets     | Compiler may optimize away                | `sodium_memzero`               |
| `printf` for debug in core       | Breaks library boundary                   | Return error codes + log hook  |
| `exit()` in library code         | Robs caller of error handling             | Return error code              |
| `static` local buffers in core   | Not thread-safe, secrets persist in BSS   | Stack or heap allocation       |
| `rand()` / `srand()`             | Not cryptographically secure              | `randombytes_buf` (libsodium)  |
| Hardcoded paths                  | Platform-specific                         | `g_get_user_data_dir()`        |
| `atoi()` / `atof()`             | No error detection                        | `strtol()` / `strtod()`        |
| Global mutable state in core     | Not testable, not thread-safe             | Pass state through structs     |
