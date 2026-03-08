/*
 * VaultC — Database CRUD Operations
 * File: include/vaultc/db.h
 */

#ifndef VAULTC_DB_H
#define VAULTC_DB_H

#include <stdint.h>
#include <stddef.h>

#include "vaultc/types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /* ═══════════════════════════════════════════════════════════════════════
     * Database CRUD Functions
     *
     * The `db` parameter is a sqlite3* obtained via vault_get_db(handle).
     * All SQL uses prepared statements — never string interpolation.
     * ═══════════════════════════════════════════════════════════════════════ */

    /**
     * Create a new entry in the database.
     *
     * @param db    SQLite3 database handle (cast from void*).
     * @param entry Populated Entry struct. The uuid field must be set.
     * @return      VAULTC_OK on success, VAULTC_ERR_DUPLICATE if UUID exists,
     *              VAULTC_ERR_INVALID_ARG if db or entry is NULL,
     *              VAULTC_ERR_DB on SQLite error.
     */
    VaultcError db_entry_create(void *db, const Entry *entry);

    /**
     * Read a single entry by UUID.
     *
     * @param db   SQLite3 database handle.
     * @param uuid Null-terminated UUID string.
     * @return     Heap-allocated Entry on success (caller must call
     *             db_free_entry()), or NULL if not found or on error.
     */
    Entry *db_entry_read(void *db, const char *uuid);

    /**
     * Update an existing entry (matched by uuid).
     *
     * @param db    SQLite3 database handle.
     * @param entry Entry with updated fields. uuid must match an existing row.
     * @return      VAULTC_OK on success, VAULTC_ERR_NOT_FOUND if uuid absent,
     *              VAULTC_ERR_INVALID_ARG if db or entry is NULL,
     *              VAULTC_ERR_DB on SQLite error.
     */
    VaultcError db_entry_update(void *db, const Entry *entry);

    /**
     * Delete an entry by UUID.
     *
     * @param db   SQLite3 database handle.
     * @param uuid Null-terminated UUID string.
     * @return     VAULTC_OK on success, VAULTC_ERR_NOT_FOUND if uuid absent,
     *             VAULTC_ERR_INVALID_ARG if db or uuid is NULL,
     *             VAULTC_ERR_DB on SQLite error.
     */
    VaultcError db_entry_delete(void *db, const char *uuid);

    /**
     * List entries, optionally filtered by a LIKE pattern on
     * title, url, or username.
     *
     * @param db     SQLite3 database handle.
     * @param filter Nullable substring filter (SQL LIKE %filter%).
     *               Pass NULL to list all entries.
     * @return       Heap-allocated EntryList (caller must call
     *               db_free_entry_list()), or NULL on error.
     */
    EntryList *db_entry_list(void *db, const char *filter);

    /**
     * Search entries by a query string matching title, url, or username.
     * Results are ordered by updated_at DESC.
     *
     * @param db    SQLite3 database handle.
     * @param query Search substring (wrapped in %...% for LIKE).
     * @return      Heap-allocated EntryList (caller must call
     *              db_free_entry_list()), or NULL on error.
     */
    EntryList *db_entry_search(void *db, const char *query);

    /**
     * Free a single Entry and zero sensitive fields first.
     *
     * Calls crypto_secure_zero on password and totp_secret before freeing.
     *
     * @param entry Entry to free. NULL is a safe no-op.
     */
    void db_free_entry(Entry *entry);

    /**
     * Free an EntryList and all entries it contains.
     *
     * @param list EntryList to free. NULL is a safe no-op.
     */
    void db_free_entry_list(EntryList *list);

#ifdef __cplusplus
}
#endif

#endif /* VAULTC_DB_H */
