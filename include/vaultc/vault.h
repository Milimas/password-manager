/*
 * VaultC — Vault I/O Operations
 * File: include/vaultc/vault.h
 */

#ifndef VAULTC_VAULT_H
#define VAULTC_VAULT_H

#include <stdint.h>
#include <stddef.h>

#include "vaultc/types.h"
#include "vaultc/crypto.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /* --- Constants --- */

#define VAULTC_MAGIC_0 0x56 /* 'V' */
#define VAULTC_MAGIC_1 0x41 /* 'A' */
#define VAULTC_MAGIC_2 0x55 /* 'U' */
#define VAULTC_MAGIC_3 0x4C /* 'L' */
#define VAULTC_VERSION 1U
#define VAULTC_HEADER_NONCE_BYTES 16 /* nonce field in file header    */

#define VAULTC_DEFAULT_KDF_OPS 3U        /* crypto_pwhash_OPSLIMIT_MODERATE */
#define VAULTC_DEFAULT_KDF_MEM 67108864U /* crypto_pwhash_MEMLIMIT_MODERATE (64 MiB) */

    /* --- Vault File Header (binary, packed) --- */

#pragma pack(push, 1)
    typedef struct
    {
        uint8_t magic[4];
        uint32_t version;
        uint32_t flags;
        uint8_t salt[VAULTC_SALT_BYTES];
        uint8_t nonce[VAULTC_HEADER_NONCE_BYTES];
        uint32_t kdf_mem;
        uint32_t kdf_ops;
        uint64_t ciphertext_len;
        uint8_t tag[VAULTC_TAG_BYTES];
    } VaultFileHeader;
#pragma pack(pop)

    _Static_assert(sizeof(VaultFileHeader) == 92,
                   "VaultFileHeader must be exactly 92 bytes");

    /* --- Opaque handle (definition in vault.c) --- */

    typedef struct VaultHandle VaultHandle;

    /**
     * Create a new vault file with an empty database.
     *
     * @param path             Path where the .vcf file will be written.
     * @param master_password  Null-terminated master password string.
     *
     * @return Pointer to a new VaultHandle on success, NULL on failure.
     *         Caller must call vault_close() when done.
     */
    VaultHandle *vault_create(const char *path, const char *master_password);

    /**
     * Open an existing vault file.
     *
     * @param path             Path to the .vcf vault file.
     * @param master_password  Null-terminated master password string.
     *
     * @return Pointer to VaultHandle on success, NULL on failure.
     *         Returns NULL with VAULTC_ERR_BAD_PASSWORD if the password is wrong.
     *         Returns NULL with VAULTC_ERR_CORRUPT if the file is invalid.
     *         Caller must call vault_close() when done.
     */
    VaultHandle *vault_open(const char *path, const char *master_password);

    /**
     * Save the vault back to disk using atomic write (temp file + rename).
     * Generates a fresh nonce for every save.
     *
     * @param handle  Open vault handle.
     *
     * @return VAULTC_OK on success, negative error code on failure.
     */
    VaultcError vault_save(VaultHandle *handle);

    /**
     * Lock and close the vault, zeroing all key material.
     *
     * @param handle  Vault handle to close. Pointer is invalid after this call.
     *
     * @warning After this call, handle must not be used.
     */
    void vault_close(VaultHandle *handle);

    /**
     * Change the master password of an open vault.
     * Re-derives the key with the new password and saves the vault.
     *
     * @param handle        Open vault handle.
     * @param old_password  Current master password (for verification).
     * @param new_password  New master password to set.
     *
     * @return VAULTC_OK on success,
     *         VAULTC_ERR_BAD_PASSWORD if old_password doesn't match,
     *         VAULTC_ERR_INVALID_ARG if any argument is NULL.
     */
    VaultcError vault_change_password(VaultHandle *handle,
                                      const char *old_password,
                                      const char *new_password);

    /**
     * Get the SQLite database handle from a vault (for db.c operations).
     *
     * @param handle  Open vault handle.
     * @return        sqlite3 pointer (opaque void* to avoid leaking sqlite3.h).
     *                Returns NULL if handle is NULL.
     *
     * @note Caller must NOT close the returned database — vault_close does that.
     */
    void *vault_get_db(VaultHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* VAULTC_VAULT_H */
