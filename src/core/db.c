/*
 * VaultC — Database CRUD Operations (SQLite3)
 * File: src/core/db.c
 */

#include "vaultc/db.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sqlite3.h>

#include "vaultc/crypto.h"

/* ── Internal: duplicate a string (NULL-safe) ──────────────────────────────── */

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

/* ── Internal: write an audit log entry ────────────────────────────────────── */

static void db_audit_log(sqlite3 *sdb, const char *entry_uuid,
                         const char *action)
{
    const char *sql =
        "INSERT INTO audit_log (entry_uuid, action, timestamp)"
        " VALUES (?1, ?2, ?3);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(sdb, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        /* Best-effort: audit logging failure is non-fatal */
        return;
    }

    sqlite3_bind_text(stmt, 1, entry_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, action, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (int64_t)time(NULL));

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

/* ── Internal: populate an Entry from a SELECT result row ──────────────────── */

static Entry *entry_from_row(sqlite3_stmt *stmt)
{
    Entry *e = calloc(1, sizeof(Entry));
    if (e == NULL)
    {
        return NULL;
    }

    /* Column order matches: uuid, title, url, username, password,
       notes, totp_secret, category, is_favorite, created_at,
       updated_at, last_used, source */

    const char *uuid = (const char *)sqlite3_column_text(stmt, 0);
    if (uuid != NULL)
    {
        strncpy(e->uuid, uuid, VAULTC_UUID_LEN - 1);
        e->uuid[VAULTC_UUID_LEN - 1] = '\0';
    }

    e->title       = safe_strdup((const char *)sqlite3_column_text(stmt, 1));
    e->url         = safe_strdup((const char *)sqlite3_column_text(stmt, 2));
    e->username    = safe_strdup((const char *)sqlite3_column_text(stmt, 3));
    e->password    = safe_strdup((const char *)sqlite3_column_text(stmt, 4));
    e->notes       = safe_strdup((const char *)sqlite3_column_text(stmt, 5));
    e->totp_secret = safe_strdup((const char *)sqlite3_column_text(stmt, 6));
    e->category    = safe_strdup((const char *)sqlite3_column_text(stmt, 7));
    e->is_favorite = sqlite3_column_int(stmt, 8);
    e->created_at  = sqlite3_column_int64(stmt, 9);
    e->updated_at  = sqlite3_column_int64(stmt, 10);
    e->last_used   = sqlite3_column_int64(stmt, 11);
    e->source      = safe_strdup((const char *)sqlite3_column_text(stmt, 12));

    return e;
}

/* ── Internal: build an EntryList from a prepared SELECT statement ─────────── */

static EntryList *list_from_stmt(sqlite3_stmt *stmt)
{
    EntryList *list = calloc(1, sizeof(EntryList));
    if (list == NULL)
    {
        return NULL;
    }

    list->capacity = 16;
    list->items = malloc(list->capacity * sizeof(Entry *));
    if (list->items == NULL)
    {
        free(list);
        return NULL;
    }
    list->count = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        if (list->count == list->capacity)
        {
            list->capacity *= 2;
            Entry **tmp = realloc(list->items,
                                  list->capacity * sizeof(Entry *));
            if (tmp == NULL)
            {
                /* Free what we have and bail */
                for (size_t i = 0; i < list->count; i++)
                {
                    db_free_entry(list->items[i]);
                }
                free(list->items);
                free(list);
                return NULL;
            }
            list->items = tmp;
        }

        Entry *e = entry_from_row(stmt);
        if (e == NULL)
        {
            for (size_t i = 0; i < list->count; i++)
            {
                db_free_entry(list->items[i]);
            }
            free(list->items);
            free(list);
            return NULL;
        }
        list->items[list->count++] = e;
    }

    return list;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

VaultcError db_entry_create(void *db, const Entry *entry)
{
    if (db == NULL || entry == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    sqlite3 *sdb = (sqlite3 *)db;

    const char *sql =
        "INSERT INTO entries"
        " (uuid, title, url, username, password, notes, totp_secret,"
        "  category, is_favorite, created_at, updated_at, last_used, source)"
        " VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(sdb, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        return VAULTC_ERR_DB;
    }

    sqlite3_bind_text(stmt, 1, entry->uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, entry->title, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, entry->url, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, entry->username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, entry->password, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, entry->notes, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, entry->totp_secret, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, entry->category, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 9, entry->is_favorite);
    sqlite3_bind_int64(stmt, 10, entry->created_at);
    sqlite3_bind_int64(stmt, 11, entry->updated_at);
    sqlite3_bind_int64(stmt, 12, entry->last_used);
    sqlite3_bind_text(stmt, 13, entry->source, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
    {
        /* SQLITE_CONSTRAINT covers UNIQUE violation on uuid */
        if (rc == SQLITE_CONSTRAINT)
        {
            return VAULTC_ERR_DUPLICATE;
        }
        return VAULTC_ERR_DB;
    }

    db_audit_log(sdb, entry->uuid, "create");
    return VAULTC_OK;
}

Entry *db_entry_read(void *db, const char *uuid)
{
    if (db == NULL || uuid == NULL)
    {
        return NULL;
    }

    sqlite3 *sdb = (sqlite3 *)db;

    const char *sql =
        "SELECT uuid, title, url, username, password, notes, totp_secret,"
        " category, is_favorite, created_at, updated_at, last_used, source"
        " FROM entries WHERE uuid = ?1;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(sdb, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        return NULL;
    }

    sqlite3_bind_text(stmt, 1, uuid, -1, SQLITE_TRANSIENT);

    Entry *entry = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        entry = entry_from_row(stmt);
    }

    sqlite3_finalize(stmt);
    return entry;
}

VaultcError db_entry_update(void *db, const Entry *entry)
{
    if (db == NULL || entry == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    sqlite3 *sdb = (sqlite3 *)db;

    const char *sql =
        "UPDATE entries SET"
        " title = ?1, url = ?2, username = ?3, password = ?4,"
        " notes = ?5, totp_secret = ?6, category = ?7,"
        " is_favorite = ?8, updated_at = ?9, last_used = ?10,"
        " source = ?11"
        " WHERE uuid = ?12;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(sdb, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        return VAULTC_ERR_DB;
    }

    sqlite3_bind_text(stmt, 1, entry->title, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, entry->url, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, entry->username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, entry->password, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, entry->notes, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, entry->totp_secret, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, entry->category, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 8, entry->is_favorite);
    sqlite3_bind_int64(stmt, 9, entry->updated_at);
    sqlite3_bind_int64(stmt, 10, entry->last_used);
    sqlite3_bind_text(stmt, 11, entry->source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, entry->uuid, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
    {
        return VAULTC_ERR_DB;
    }

    /* sqlite3_changes() returns 0 if no row matched the WHERE clause */
    if (sqlite3_changes(sdb) == 0)
    {
        return VAULTC_ERR_NOT_FOUND;
    }

    db_audit_log(sdb, entry->uuid, "update");
    return VAULTC_OK;
}

VaultcError db_entry_delete(void *db, const char *uuid)
{
    if (db == NULL || uuid == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    sqlite3 *sdb = (sqlite3 *)db;

    const char *sql = "DELETE FROM entries WHERE uuid = ?1;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(sdb, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        return VAULTC_ERR_DB;
    }

    sqlite3_bind_text(stmt, 1, uuid, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
    {
        return VAULTC_ERR_DB;
    }

    if (sqlite3_changes(sdb) == 0)
    {
        return VAULTC_ERR_NOT_FOUND;
    }

    db_audit_log(sdb, uuid, "delete");
    return VAULTC_OK;
}

EntryList *db_entry_list(void *db, const char *filter)
{
    if (db == NULL)
    {
        return NULL;
    }

    sqlite3 *sdb = (sqlite3 *)db;
    sqlite3_stmt *stmt = NULL;

    if (filter == NULL)
    {
        const char *sql =
            "SELECT uuid, title, url, username, password, notes,"
            " totp_secret, category, is_favorite, created_at,"
            " updated_at, last_used, source"
            " FROM entries ORDER BY updated_at DESC;";

        if (sqlite3_prepare_v2(sdb, sql, -1, &stmt, NULL) != SQLITE_OK)
        {
            return NULL;
        }
    }
    else
    {
        const char *sql =
            "SELECT uuid, title, url, username, password, notes,"
            " totp_secret, category, is_favorite, created_at,"
            " updated_at, last_used, source"
            " FROM entries"
            " WHERE title LIKE ?1 OR url LIKE ?1 OR username LIKE ?1"
            " ORDER BY updated_at DESC;";

        if (sqlite3_prepare_v2(sdb, sql, -1, &stmt, NULL) != SQLITE_OK)
        {
            return NULL;
        }

        /* Build %filter% pattern */
        size_t flen = strlen(filter);
        char *pattern = malloc(flen + 3); /* '%' + filter + '%' + '\0' */
        if (pattern == NULL)
        {
            sqlite3_finalize(stmt);
            return NULL;
        }
        pattern[0] = '%';
        memcpy(pattern + 1, filter, flen);
        pattern[flen + 1] = '%';
        pattern[flen + 2] = '\0';

        sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_TRANSIENT);
        free(pattern);
    }

    EntryList *list = list_from_stmt(stmt);
    sqlite3_finalize(stmt);
    return list;
}

EntryList *db_entry_search(void *db, const char *query)
{
    if (db == NULL || query == NULL)
    {
        return NULL;
    }

    sqlite3 *sdb = (sqlite3 *)db;

    const char *sql =
        "SELECT uuid, title, url, username, password, notes,"
        " totp_secret, category, is_favorite, created_at,"
        " updated_at, last_used, source"
        " FROM entries"
        " WHERE title LIKE ?1 OR url LIKE ?1 OR username LIKE ?1"
        " ORDER BY updated_at DESC;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(sdb, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        return NULL;
    }

    /* Build %query% pattern */
    size_t qlen = strlen(query);
    char *pattern = malloc(qlen + 3);
    if (pattern == NULL)
    {
        sqlite3_finalize(stmt);
        return NULL;
    }
    pattern[0] = '%';
    memcpy(pattern + 1, query, qlen);
    pattern[qlen + 1] = '%';
    pattern[qlen + 2] = '\0';

    sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_TRANSIENT);
    free(pattern);

    EntryList *list = list_from_stmt(stmt);
    sqlite3_finalize(stmt);
    return list;
}

void db_free_entry(Entry *entry)
{
    if (entry == NULL)
    {
        return;
    }

    /* Securely zero sensitive fields before freeing */
    if (entry->password != NULL)
    {
        crypto_secure_zero(entry->password, strlen(entry->password));
        free(entry->password);
    }
    if (entry->totp_secret != NULL)
    {
        crypto_secure_zero(entry->totp_secret, strlen(entry->totp_secret));
        free(entry->totp_secret);
    }

    /* Free remaining heap-allocated fields */
    free(entry->title);
    free(entry->url);
    free(entry->username);
    free(entry->notes);
    free(entry->category);
    free(entry->source);

    free(entry);
}

void db_free_entry_list(EntryList *list)
{
    if (list == NULL)
    {
        return;
    }

    for (size_t i = 0; i < list->count; i++)
    {
        db_free_entry(list->items[i]);
    }

    free(list->items);
    free(list);
}
