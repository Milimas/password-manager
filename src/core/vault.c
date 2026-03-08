/*
 * VaultC — Vault File I/O (create, open, save, close)
 * File: src/core/vault.c
 */

#include "vaultc/vault.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>
#include <sqlite3.h>

#include "vaultc/crypto.h"

/* ── Private struct definition (opaque outside this file) ──────────────────── */

struct VaultHandle
{
    sqlite3 *db;
    uint8_t key[VAULTC_KEY_BYTES];
    uint8_t salt[VAULTC_SALT_BYTES];
    char *path;
    uint32_t kdf_ops;
    uint32_t kdf_mem;
    int is_modified;
};

/* ── SQL schema executed on vault creation ─────────────────────────────────── */

static const char *const SCHEMA_SQL =
    "CREATE TABLE entries ("
    "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  uuid        TEXT NOT NULL UNIQUE,"
    "  title       TEXT NOT NULL,"
    "  url         TEXT,"
    "  username    TEXT,"
    "  password    TEXT NOT NULL,"
    "  notes       TEXT,"
    "  totp_secret TEXT,"
    "  category    TEXT DEFAULT 'General',"
    "  is_favorite INTEGER DEFAULT 0,"
    "  created_at  INTEGER NOT NULL,"
    "  updated_at  INTEGER NOT NULL,"
    "  last_used   INTEGER,"
    "  source      TEXT DEFAULT 'manual'"
    ");"
    "CREATE TABLE tags ("
    "  id   INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  name TEXT NOT NULL UNIQUE"
    ");"
    "CREATE TABLE entry_tags ("
    "  entry_id INTEGER REFERENCES entries(id) ON DELETE CASCADE,"
    "  tag_id   INTEGER REFERENCES tags(id) ON DELETE CASCADE,"
    "  PRIMARY KEY (entry_id, tag_id)"
    ");"
    "CREATE TABLE audit_log ("
    "  id         INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  entry_uuid TEXT,"
    "  action     TEXT NOT NULL,"
    "  timestamp  INTEGER NOT NULL"
    ");"
    "CREATE TABLE metadata ("
    "  key   TEXT PRIMARY KEY,"
    "  value TEXT NOT NULL"
    ");"
    "INSERT INTO metadata (key, value) VALUES ('vault_name', 'My Vault');"
    "INSERT INTO metadata (key, value) VALUES ('schema_version', '1');"
    "INSERT INTO metadata (key, value) VALUES ('created_at', "
    "  CAST(strftime('%s', 'now') AS INTEGER));";

/* ── Helper: duplicate a string (checks NULL) ─────────────────────────────── */

static char *safe_strdup(const char *s)
{
    if (s == NULL)
    {
        return NULL;
    }
    char *copy = malloc(strlen(s) + 1);
    if (copy == NULL)
    {
        abort(); /* OOM is unrecoverable */
    }
    strcpy(copy, s);
    return copy;
}

/* ── Helper: validate magic bytes ──────────────────────────────────────────── */

static int header_magic_valid(const VaultFileHeader *h)
{
    return h->magic[0] == VAULTC_MAGIC_0 &&
           h->magic[1] == VAULTC_MAGIC_1 &&
           h->magic[2] == VAULTC_MAGIC_2 &&
           h->magic[3] == VAULTC_MAGIC_3;
}

/* ── Helper: build a temp path for atomic writes ──────────────────────────── */

static char *make_tmp_path(const char *path)
{
    size_t len = strlen(path);
    char *tmp = malloc(len + 5); /* ".tmp" + NUL */
    if (tmp == NULL)
    {
        abort();
    }
    memcpy(tmp, path, len);
    memcpy(tmp + len, ".tmp", 5); /* includes NUL */
    return tmp;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * vault_create — Task 2.2
 * ═══════════════════════════════════════════════════════════════════════════ */

VaultHandle *vault_create(const char *path, const char *master_password)
{
    if (path == NULL || master_password == NULL)
    {
        return NULL;
    }

    VaultHandle *handle = NULL;

    handle = calloc(1, sizeof(VaultHandle));
    if (handle == NULL)
    {
        return NULL;
    }

    /* Generate random salt */
    crypto_random_bytes(handle->salt, VAULTC_SALT_BYTES);

    /* Set default KDF parameters */
    handle->kdf_ops = VAULTC_DEFAULT_KDF_OPS;
    handle->kdf_mem = VAULTC_DEFAULT_KDF_MEM;

    /* Derive encryption key */
    VaultcError err = crypto_derive_key(master_password,
                                        handle->salt,
                                        handle->kdf_ops,
                                        handle->kdf_mem,
                                        handle->key);
    if (err != VAULTC_OK)
    {
        goto fail;
    }

    /* Open in-memory SQLite database */
    int rc = sqlite3_open(":memory:", &handle->db);
    if (rc != SQLITE_OK)
    {
        goto fail;
    }

    /* Execute schema SQL */
    char *sql_err = NULL;
    rc = sqlite3_exec(handle->db, SCHEMA_SQL, NULL, NULL, &sql_err);
    if (rc != SQLITE_OK)
    {
        sqlite3_free(sql_err);
        goto fail;
    }

    handle->path = safe_strdup(path);
    handle->is_modified = 1;

    /* Write the initial encrypted vault file to disk */
    err = vault_save(handle);
    if (err != VAULTC_OK)
    {
        goto fail;
    }

    return handle;

fail:
    if (handle != NULL)
    {
        if (handle->db != NULL)
        {
            sqlite3_close(handle->db);
        }
        crypto_secure_zero(handle->key, sizeof(handle->key));
        free(handle->path);
        handle->path = NULL;
        free(handle);
        handle = NULL;
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * vault_open — Task 2.3
 * ═══════════════════════════════════════════════════════════════════════════ */

VaultHandle *vault_open(const char *path, const char *master_password)
{
    if (path == NULL || master_password == NULL)
    {
        return NULL;
    }

    VaultHandle *handle = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *plaintext = NULL;
    FILE *f = NULL;

    /* Open the vault file */
    f = fopen(path, "rb");
    if (f == NULL)
    {
        return NULL;
    }

    /* Read and validate header */
    VaultFileHeader header;
    size_t n = fread(&header, 1, sizeof(header), f);
    if (n != sizeof(header))
    {
        goto fail;
    }

    if (!header_magic_valid(&header))
    {
        goto fail;
    }

    if (header.version != VAULTC_VERSION)
    {
        goto fail;
    }

    if (header.ciphertext_len == 0)
    {
        goto fail;
    }

    /* Allocate handle */
    handle = calloc(1, sizeof(VaultHandle));
    if (handle == NULL)
    {
        goto fail;
    }

    memcpy(handle->salt, header.salt, VAULTC_SALT_BYTES);
    handle->kdf_ops = header.kdf_ops;
    handle->kdf_mem = header.kdf_mem;

    /* Derive key from password */
    VaultcError err = crypto_derive_key(master_password,
                                        handle->salt,
                                        handle->kdf_ops,
                                        handle->kdf_mem,
                                        handle->key);
    if (err != VAULTC_OK)
    {
        goto fail;
    }

    /* Read ciphertext */
    ciphertext = malloc((size_t)header.ciphertext_len);
    if (ciphertext == NULL)
    {
        goto fail;
    }

    n = fread(ciphertext, 1, (size_t)header.ciphertext_len, f);
    if (n != (size_t)header.ciphertext_len)
    {
        goto fail;
    }

    fclose(f);
    f = NULL;

    /* Decrypt */
    plaintext = malloc((size_t)header.ciphertext_len);
    if (plaintext == NULL)
    {
        goto fail;
    }

    err = crypto_decrypt(ciphertext,
                         (size_t)header.ciphertext_len,
                         handle->key,
                         header.nonce,
                         header.tag,
                         plaintext);
    if (err != VAULTC_OK)
    {
        /* Wrong password or corrupted file */
        goto fail;
    }

    /* Open in-memory SQLite and deserialize */
    int rc = sqlite3_open(":memory:", &handle->db);
    if (rc != SQLITE_OK)
    {
        goto fail;
    }

    /*
     * sqlite3_deserialize takes ownership of the buffer if we pass
     * SQLITE_DESERIALIZE_FREEONCLOSE. But we need to zero the plaintext
     * for security before freeing, so we make a copy for SQLite.
     */
    uint8_t *db_buf = sqlite3_malloc64((sqlite3_int64)header.ciphertext_len);
    if (db_buf == NULL)
    {
        goto fail;
    }
    memcpy(db_buf, plaintext, (size_t)header.ciphertext_len);

    /* Zero and free our plaintext copy */
    crypto_secure_zero(plaintext, (size_t)header.ciphertext_len);
    free(plaintext);
    plaintext = NULL;

    rc = sqlite3_deserialize(handle->db, "main", db_buf,
                             (sqlite3_int64)header.ciphertext_len,
                             (sqlite3_int64)header.ciphertext_len,
                             SQLITE_DESERIALIZE_FREEONCLOSE |
                                 SQLITE_DESERIALIZE_RESIZEABLE);
    if (rc != SQLITE_OK)
    {
        goto fail;
    }

    /* Clean up ciphertext */
    crypto_secure_zero(ciphertext, (size_t)header.ciphertext_len);
    free(ciphertext);
    ciphertext = NULL;

    handle->path = safe_strdup(path);
    handle->is_modified = 0;

    return handle;

fail:
    if (f != NULL)
    {
        fclose(f);
    }
    if (plaintext != NULL)
    {
        crypto_secure_zero(plaintext, (size_t)header.ciphertext_len);
        free(plaintext);
    }
    if (ciphertext != NULL)
    {
        crypto_secure_zero(ciphertext, (size_t)header.ciphertext_len);
        free(ciphertext);
    }
    if (handle != NULL)
    {
        if (handle->db != NULL)
        {
            sqlite3_close(handle->db);
        }
        crypto_secure_zero(handle->key, sizeof(handle->key));
        free(handle->path);
        free(handle);
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * vault_save — Task 2.4  (atomic: temp file + rename)
 * ═══════════════════════════════════════════════════════════════════════════ */

VaultcError vault_save(VaultHandle *handle)
{
    if (handle == NULL || handle->db == NULL || handle->path == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    uint8_t *raw_db = NULL;
    uint8_t *ciphertext = NULL;
    char *tmp_path = NULL;
    FILE *f = NULL;

    /* Serialize the in-memory database */
    sqlite3_int64 raw_len = 0;
    raw_db = sqlite3_serialize(handle->db, "main", &raw_len, 0);
    if (raw_db == NULL || raw_len <= 0)
    {
        return VAULTC_ERR_DB;
    }

    /* Generate a fresh nonce for this save */
    uint8_t nonce[VAULTC_NONCE_BYTES];
    crypto_random_bytes(nonce, sizeof(nonce));

    /* Encrypt */
    ciphertext = malloc((size_t)raw_len);
    if (ciphertext == NULL)
    {
        goto fail_nomem;
    }

    uint8_t tag[VAULTC_TAG_BYTES];
    VaultcError err = crypto_encrypt(raw_db,
                                     (size_t)raw_len,
                                     handle->key,
                                     nonce,
                                     ciphertext,
                                     tag);
    if (err != VAULTC_OK)
    {
        goto fail_crypto;
    }

    /* Build header */
    VaultFileHeader header;
    memset(&header, 0, sizeof(header));
    header.magic[0] = VAULTC_MAGIC_0;
    header.magic[1] = VAULTC_MAGIC_1;
    header.magic[2] = VAULTC_MAGIC_2;
    header.magic[3] = VAULTC_MAGIC_3;
    header.version = VAULTC_VERSION;
    header.flags = 0;
    memcpy(header.salt, handle->salt, VAULTC_SALT_BYTES);
    /* Copy nonce into the 16-byte header field (pad remaining with zero) */
    memset(header.nonce, 0, VAULTC_HEADER_NONCE_BYTES);
    memcpy(header.nonce, nonce, VAULTC_NONCE_BYTES);
    header.kdf_mem = handle->kdf_mem;
    header.kdf_ops = handle->kdf_ops;
    header.ciphertext_len = (uint64_t)raw_len;
    memcpy(header.tag, tag, VAULTC_TAG_BYTES);

    /* Atomic write: write to .tmp, then rename */
    tmp_path = make_tmp_path(handle->path);

    f = fopen(tmp_path, "wb");
    if (f == NULL)
    {
        goto fail_io;
    }

    size_t written = fwrite(&header, 1, sizeof(header), f);
    if (written != sizeof(header))
    {
        goto fail_io;
    }

    written = fwrite(ciphertext, 1, (size_t)raw_len, f);
    if (written != (size_t)raw_len)
    {
        goto fail_io;
    }

    if (fclose(f) != 0)
    {
        f = NULL;
        goto fail_io;
    }
    f = NULL;

    /* Atomic rename */
    if (rename(tmp_path, handle->path) != 0)
    {
        /* Try to clean up the temp file */
        remove(tmp_path);
        goto fail_io;
    }

    handle->is_modified = 0;

    /* Clean up */
    crypto_secure_zero(raw_db, (size_t)raw_len);
    sqlite3_free(raw_db);
    raw_db = NULL;
    crypto_secure_zero(ciphertext, (size_t)raw_len);
    free(ciphertext);
    ciphertext = NULL;
    free(tmp_path);
    tmp_path = NULL;

    return VAULTC_OK;

fail_nomem:
    err = VAULTC_ERR_NOMEM;
    goto cleanup;

fail_crypto:
    /* err already set */
    goto cleanup;

fail_io:
    err = VAULTC_ERR_IO;
    goto cleanup;

cleanup:
    if (f != NULL)
    {
        fclose(f);
    }
    if (tmp_path != NULL)
    {
        remove(tmp_path);
        free(tmp_path);
    }
    if (ciphertext != NULL)
    {
        crypto_secure_zero(ciphertext, (size_t)raw_len);
        free(ciphertext);
    }
    if (raw_db != NULL)
    {
        crypto_secure_zero(raw_db, (size_t)raw_len);
        sqlite3_free(raw_db);
    }
    return err;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * vault_close — Task 2.5
 * ═══════════════════════════════════════════════════════════════════════════ */

void vault_close(VaultHandle *handle)
{
    if (handle == NULL)
    {
        return;
    }

    if (handle->db != NULL)
    {
        sqlite3_close(handle->db);
        handle->db = NULL;
    }

    crypto_secure_zero(handle->key, sizeof(handle->key));
    crypto_secure_zero(handle->salt, sizeof(handle->salt));

    free(handle->path);
    handle->path = NULL;

    free(handle);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * vault_change_password
 * ═══════════════════════════════════════════════════════════════════════════ */

VaultcError vault_change_password(VaultHandle *handle,
                                  const char *old_password,
                                  const char *new_password)
{
    if (handle == NULL || old_password == NULL || new_password == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    /* Verify old password by deriving key and comparing */
    uint8_t verify_key[VAULTC_KEY_BYTES];
    VaultcError err = crypto_derive_key(old_password,
                                        handle->salt,
                                        handle->kdf_ops,
                                        handle->kdf_mem,
                                        verify_key);
    if (err != VAULTC_OK)
    {
        crypto_secure_zero(verify_key, sizeof(verify_key));
        return err;
    }

    if (sodium_memcmp(verify_key, handle->key, VAULTC_KEY_BYTES) != 0)
    {
        crypto_secure_zero(verify_key, sizeof(verify_key));
        return VAULTC_ERR_BAD_PASSWORD;
    }
    crypto_secure_zero(verify_key, sizeof(verify_key));

    /* Generate new salt and derive new key */
    crypto_random_bytes(handle->salt, VAULTC_SALT_BYTES);

    err = crypto_derive_key(new_password,
                            handle->salt,
                            handle->kdf_ops,
                            handle->kdf_mem,
                            handle->key);
    if (err != VAULTC_OK)
    {
        return err;
    }

    /* Save with new key */
    return vault_save(handle);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * vault_get_db
 * ═══════════════════════════════════════════════════════════════════════════ */

void *vault_get_db(VaultHandle *handle)
{
    if (handle == NULL)
    {
        return NULL;
    }
    return handle->db;
}
