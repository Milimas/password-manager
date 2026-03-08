/*
 * VaultC — Application Session State
 * File: include/vaultc/session.h
 *
 * Provides the bridge between the UI layer and vault/db/import layers.
 * All UI code calls session functions — never vault/db directly.
 */

#ifndef VAULTC_SESSION_H
#define VAULTC_SESSION_H

#include "vaultc/types.h"
#include "vaultc/vault.h"
#include "vaultc/db.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Global application session state.
     */
    typedef struct
    {
        VaultHandle *vault; /**< Open vault handle (NULL if locked)  */
        char *vault_path;   /**< Path to the .vcf vault file         */
        int is_locked;      /**< 1 if locked, 0 if open              */
    } AppSession;

    /** Global session instance. */
    extern AppSession g_session;

    /**
     * Get the default vault file path.
     * Returns g_get_user_data_dir()/vaultc/vault.vcf.
     * Caller must g_free() the result.
     */
    char *session_get_vault_path(void);

    /**
     * Check if a vault file exists at the default path.
     */
    int session_vault_exists(void);

    /**
     * Create a new vault at the default path.
     *
     * @param master_password  Password for the new vault.
     * @return VAULTC_OK on success.
     */
    VaultcError session_create_vault(const char *master_password);

    /**
     * Open an existing vault at the default path.
     *
     * @param master_password  Master password to unlock.
     * @return VAULTC_OK on success, VAULTC_ERR_BAD_PASSWORD on wrong password.
     */
    VaultcError session_open_vault(const char *master_password);

    /**
     * Lock the vault (close handle, zero key material).
     */
    void session_lock(void);

    /**
     * Save the current vault to disk.
     * @return VAULTC_OK on success.
     */
    VaultcError session_save(void);

    /**
     * Get the SQLite database handle from the open vault.
     * @return sqlite3* (as void*), or NULL if locked.
     */
    void *session_get_db(void);

    /**
     * Create a new entry via the session.
     */
    VaultcError session_entry_create(const Entry *entry);

    /**
     * Update an entry via the session.
     */
    VaultcError session_entry_update(const Entry *entry);

    /**
     * Delete an entry by UUID via the session.
     */
    VaultcError session_entry_delete(const char *uuid);

    /**
     * List entries, optionally filtered.
     * Caller must db_free_entry_list() the result.
     */
    EntryList *session_entry_list(const char *filter);

    /**
     * Search entries.
     * Caller must db_free_entry_list() the result.
     */
    EntryList *session_entry_search(const char *query);

    /**
     * Change the vault master password.
     */
    VaultcError session_change_password(const char *old_pw,
                                        const char *new_pw);

#ifdef __cplusplus
}
#endif

#endif /* VAULTC_SESSION_H */
