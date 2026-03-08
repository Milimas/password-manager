/*
 * VaultC — Application Session State
 * File: src/app/session.c
 *
 * Bridge between UI layer and vault/db/import layers.
 */

#include "vaultc/session.h"

#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "vaultc/crypto.h"

/* ── Global session instance ───────────────────────────────────────────────── */

AppSession g_session = {
    .vault = NULL,
    .vault_path = NULL,
    .is_locked = 1,
};

/* ── Default vault path ────────────────────────────────────────────────────── */

char *session_get_vault_path(void)
{
    const char *data_dir = g_get_user_data_dir();
    return g_build_filename(data_dir, "vaultc", "vault.vcf", NULL);
}

int session_vault_exists(void)
{
    char *path = session_get_vault_path();
    int exists = g_file_test(path, G_FILE_TEST_EXISTS);
    g_free(path);
    return exists;
}

/* ── Create / Open / Lock ──────────────────────────────────────────────────── */

VaultcError session_create_vault(const char *master_password)
{
    if (master_password == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    char *path = session_get_vault_path();

    /* Ensure directory exists */
    char *dir = g_path_get_dirname(path);
    g_mkdir_with_parents(dir, 0700);
    g_free(dir);

    VaultHandle *vh = vault_create(path, master_password);
    if (vh == NULL)
    {
        g_free(path);
        return VAULTC_ERR_IO;
    }

    /* Close any existing session */
    session_lock();

    g_session.vault = vh;
    g_session.vault_path = path;
    g_session.is_locked = 0;

    return VAULTC_OK;
}

VaultcError session_open_vault(const char *master_password)
{
    if (master_password == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    char *path = session_get_vault_path();

    VaultHandle *vh = vault_open(path, master_password);
    if (vh == NULL)
    {
        g_free(path);
        return VAULTC_ERR_BAD_PASSWORD;
    }

    /* Close any existing session */
    session_lock();

    g_session.vault = vh;
    g_session.vault_path = path;
    g_session.is_locked = 0;

    return VAULTC_OK;
}

void session_lock(void)
{
    if (g_session.vault != NULL)
    {
        vault_close(g_session.vault);
        g_session.vault = NULL;
    }
    if (g_session.vault_path != NULL)
    {
        g_free(g_session.vault_path);
        g_session.vault_path = NULL;
    }
    g_session.is_locked = 1;
}

/* ── Save ──────────────────────────────────────────────────────────────────── */

VaultcError session_save(void)
{
    if (g_session.vault == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }
    return vault_save(g_session.vault);
}

/* ── DB access ─────────────────────────────────────────────────────────────── */

void *session_get_db(void)
{
    if (g_session.vault == NULL)
    {
        return NULL;
    }
    return vault_get_db(g_session.vault);
}

/* ── CRUD wrappers ─────────────────────────────────────────────────────────── */

VaultcError session_entry_create(const Entry *entry)
{
    void *db = session_get_db();
    if (db == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }
    VaultcError err = db_entry_create(db, entry);
    if (err == VAULTC_OK)
    {
        (void)vault_save(g_session.vault);
    }
    return err;
}

VaultcError session_entry_update(const Entry *entry)
{
    void *db = session_get_db();
    if (db == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }
    VaultcError err = db_entry_update(db, entry);
    if (err == VAULTC_OK)
    {
        (void)vault_save(g_session.vault);
    }
    return err;
}

VaultcError session_entry_delete(const char *uuid)
{
    void *db = session_get_db();
    if (db == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }
    VaultcError err = db_entry_delete(db, uuid);
    if (err == VAULTC_OK)
    {
        (void)vault_save(g_session.vault);
    }
    return err;
}

EntryList *session_entry_list(const char *filter)
{
    void *db = session_get_db();
    if (db == NULL)
    {
        return NULL;
    }
    return db_entry_list(db, filter);
}

EntryList *session_entry_search(const char *query)
{
    void *db = session_get_db();
    if (db == NULL)
    {
        return NULL;
    }
    return db_entry_search(db, query);
}

VaultcError session_change_password(const char *old_pw, const char *new_pw)
{
    if (g_session.vault == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }
    return vault_change_password(g_session.vault, old_pw, new_pw);
}
