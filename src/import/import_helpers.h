/*
 * VaultC — Shared Import Helpers (internal)
 * File: src/import/import_helpers.h
 */

#ifndef VAULTC_IMPORT_HELPERS_H
#define VAULTC_IMPORT_HELPERS_H

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sqlite3.h>

#include "vaultc/types.h"
#include "vaultc/db.h"
#include "vaultc/utils.h"

/* ── Internal: duplicate a string (NULL-safe) ──────────────────────────────── */

static inline char *import_strdup(const char *s)
{
    if (s == NULL || s[0] == '\0')
    {
        return NULL;
    }
    char *copy = malloc(strlen(s) + 1);
    if (copy == NULL)
    {
        abort();
    }
    strcpy(copy, s);
    return copy;
}

/* ── Internal: find column index by name (case-insensitive) ────────────────── */

static inline int find_col(char **hdr, int hdr_count, const char *name)
{
    for (int i = 0; i < hdr_count; i++)
    {
        const char *a = hdr[i];
        const char *b = name;
        int match = 1;
        while (*a && *b)
        {
            char ca = *a;
            char cb = *b;
            if (ca >= 'A' && ca <= 'Z')
            {
                ca = (char)(ca + 32);
            }
            if (cb >= 'A' && cb <= 'Z')
            {
                cb = (char)(cb + 32);
            }
            if (ca != cb)
            {
                match = 0;
                break;
            }
            a++;
            b++;
        }
        if (match && *a == '\0' && *b == '\0')
        {
            return i;
        }
    }
    return -1;
}

/* ── Internal: get field value by index, or empty string ───────────────────── */

static inline const char *get_field(char **fields, int count, int idx)
{
    if (idx < 0 || idx >= count)
    {
        return "";
    }
    return fields[idx] ? fields[idx] : "";
}

/* ── Internal: check for duplicate entry by URL + username ─────────────────── */

static inline int is_duplicate(void *db, const char *url, const char *username)
{
    if (db == NULL || url == NULL || username == NULL)
    {
        return 0;
    }
    if (url[0] == '\0' && username[0] == '\0')
    {
        return 0;
    }

    sqlite3 *sdb = (sqlite3 *)db;
    const char *sql =
        "SELECT COUNT(*) FROM entries"
        " WHERE url = ?1 AND username = ?2;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(sdb, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        return 0;
    }

    sqlite3_bind_text(stmt, 1, url, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);

    int dup = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        dup = sqlite3_column_int(stmt, 0) > 0;
    }

    sqlite3_finalize(stmt);
    return dup;
}

/* ── Internal: free a row of CSV fields ────────────────────────────────────── */

static inline void free_csv_fields(char **fields, int count)
{
    if (fields == NULL)
    {
        return;
    }
    for (int i = 0; i < count; i++)
    {
        free(fields[i]);
    }
    free(fields);
}

#endif /* VAULTC_IMPORT_HELPERS_H */
