/*
 * VaultC — Import Format Detection
 * File: src/import/importer.c
 */

#include "vaultc/importer.h"

#include <stdlib.h>
#include <string.h>

#include "vaultc/utils.h"

/* ── Internal: case-insensitive string comparison ──────────────────────────── */

static int ci_eq(const char *a, const char *b)
{
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
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

/* ── Internal: find a column name in the header (case-insensitive) ─────────── */

static int has_column(char **fields, int count, const char *name)
{
    for (int i = 0; i < count; i++)
    {
        if (ci_eq(fields[i], name))
        {
            return 1;
        }
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Format Detection — header row only
 * ═══════════════════════════════════════════════════════════════════════════ */

ImportFormat import_detect_format(const char *csv_path)
{
    if (csv_path == NULL)
    {
        return IMPORT_UNKNOWN;
    }

    CsvParser *p = csv_open(csv_path);
    if (p == NULL)
    {
        return IMPORT_UNKNOWN;
    }

    char **fields = NULL;
    int count = 0;
    int rc = csv_read_row(p, &fields, &count);
    csv_close(p);

    if (rc != 1 || fields == NULL || count == 0)
    {
        return IMPORT_UNKNOWN;
    }

    ImportFormat fmt = IMPORT_UNKNOWN;

    /* Bitwarden: has "folder", "type", "login_uri", "login_username",
       "login_password" */
    if (has_column(fields, count, "folder") &&
        has_column(fields, count, "type") &&
        has_column(fields, count, "login_uri") &&
        has_column(fields, count, "login_username") &&
        has_column(fields, count, "login_password"))
    {
        fmt = IMPORT_BITWARDEN;
    }
    /* Firefox: has "url", "username", "password", "httpRealm",
       "formActionOrigin" */
    else if (has_column(fields, count, "url") &&
             has_column(fields, count, "username") &&
             has_column(fields, count, "password") &&
             has_column(fields, count, "httpRealm") &&
             has_column(fields, count, "formActionOrigin"))
    {
        fmt = IMPORT_FIREFOX;
    }
    /* iOS: has "Title", "URL", "Username", "Password", "OTPAuth" */
    else if (has_column(fields, count, "Title") &&
             has_column(fields, count, "URL") &&
             has_column(fields, count, "Username") &&
             has_column(fields, count, "Password") &&
             has_column(fields, count, "OTPAuth"))
    {
        fmt = IMPORT_IOS;
    }
    /* Google: has "name", "url", "username", "password" */
    else if (has_column(fields, count, "name") &&
             has_column(fields, count, "url") &&
             has_column(fields, count, "username") &&
             has_column(fields, count, "password"))
    {
        fmt = IMPORT_GOOGLE;
    }

    /* Free header fields */
    for (int i = 0; i < count; i++)
    {
        free(fields[i]);
    }
    free(fields);

    return fmt;
}
