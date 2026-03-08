/*
 * VaultC — Firefox CSV Importer
 * File: src/import/import_firefox.c
 *
 * Firefox CSV columns: url, username, password, httpRealm,
 *   formActionOrigin, guid, timeCreated, timeLastUsed,
 *   timePasswordChanged
 */

#include "vaultc/importer.h"
#include "import_helpers.h"

#include <stdio.h>

/* ── Internal: extract hostname from URL for title derivation ──────────────── */

static char *derive_title_from_url(const char *url)
{
    /* Format: "Firefox Import — hostname" */
    const char *prefix = "Firefox Import — ";

    /* Find hostname after :// */
    const char *host_start = strstr(url, "://");
    if (host_start != NULL)
    {
        host_start += 3;
    }
    else
    {
        host_start = url;
    }

    /* Find end of hostname (at '/' or ':' or end of string) */
    const char *host_end = host_start;
    while (*host_end != '\0' && *host_end != '/' && *host_end != ':')
    {
        host_end++;
    }

    size_t host_len = (size_t)(host_end - host_start);
    size_t prefix_len = strlen(prefix);
    char *title = malloc(prefix_len + host_len + 1);
    if (title == NULL)
    {
        abort();
    }

    memcpy(title, prefix, prefix_len);
    memcpy(title + prefix_len, host_start, host_len);
    title[prefix_len + host_len] = '\0';

    return title;
}

ImportResult import_firefox_csv(void *db, const char *path)
{
    ImportResult result = {0, 0, 0, NULL, IMPORT_FIREFOX};

    if (db == NULL || path == NULL)
    {
        return result;
    }

    CsvParser *p = csv_open(path);
    if (p == NULL)
    {
        return result;
    }

    /* Read and parse header row */
    char **hdr = NULL;
    int hdr_count = 0;
    if (csv_read_row(p, &hdr, &hdr_count) != 1)
    {
        csv_close(p);
        return result;
    }

    int col_url = find_col(hdr, hdr_count, "url");
    int col_username = find_col(hdr, hdr_count, "username");
    int col_password = find_col(hdr, hdr_count, "password");

    free_csv_fields(hdr, hdr_count);

    /* Process data rows */
    char **fields = NULL;
    int count = 0;
    int64_t now = (int64_t)time(NULL);

    while (csv_read_row(p, &fields, &count) == 1)
    {
        const char *url = get_field(fields, count, col_url);
        const char *username = get_field(fields, count, col_username);

        /* Duplicate detection: URL + username */
        if (is_duplicate(db, url, username))
        {
            result.skipped_duplicates++;
            free_csv_fields(fields, count);
            continue;
        }

        Entry e;
        memset(&e, 0, sizeof(e));
        uuid_generate(e.uuid);
        e.title = derive_title_from_url(url);
        e.url = import_strdup(url);
        e.username = import_strdup(username);
        e.password = import_strdup(get_field(fields, count, col_password));
        e.category = import_strdup("General");
        e.source = import_strdup("firefox");
        e.created_at = now;
        e.updated_at = now;

        VaultcError rc = db_entry_create(db, &e);
        if (rc == VAULTC_OK)
        {
            result.imported++;
        }
        else
        {
            result.errors++;
        }

        free(e.title);
        free(e.url);
        free(e.username);
        free(e.password);
        free(e.category);
        free(e.source);
        free_csv_fields(fields, count);
    }

    csv_close(p);
    return result;
}
