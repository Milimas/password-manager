/*
 * VaultC — Google CSV Importer
 * File: src/import/import_google.c
 *
 * Google CSV columns: name, url, username, password, note
 */

#include "vaultc/importer.h"
#include "import_helpers.h"

ImportResult import_google_csv(void *db, const char *path)
{
    ImportResult result = {0, 0, 0, NULL, IMPORT_GOOGLE};

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

    int col_name = find_col(hdr, hdr_count, "name");
    int col_url = find_col(hdr, hdr_count, "url");
    int col_username = find_col(hdr, hdr_count, "username");
    int col_password = find_col(hdr, hdr_count, "password");
    int col_note = find_col(hdr, hdr_count, "note");

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
        e.title = import_strdup(get_field(fields, count, col_name));
        e.url = import_strdup(url);
        e.username = import_strdup(username);
        e.password = import_strdup(get_field(fields, count, col_password));
        e.notes = import_strdup(get_field(fields, count, col_note));
        e.category = import_strdup("General");
        e.source = import_strdup("google");
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
        free(e.notes);
        free(e.category);
        free(e.source);
        free_csv_fields(fields, count);
    }

    csv_close(p);
    return result;
}
