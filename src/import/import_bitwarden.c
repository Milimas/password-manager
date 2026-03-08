/*
 * VaultC — Bitwarden CSV Importer
 * File: src/import/import_bitwarden.c
 *
 * Bitwarden CSV columns: folder, favorite, type, name, notes, fields,
 *   reprompt, login_uri, login_username, login_password, login_totp
 *
 * Only rows with type == "login" are imported. Cards, identities, etc.
 * are skipped silently (not counted as errors).
 */

#include "vaultc/importer.h"
#include "import_helpers.h"

ImportResult import_bitwarden_csv(void *db, const char *path)
{
    ImportResult result = {0, 0, 0, NULL, IMPORT_BITWARDEN};

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

    int col_folder = find_col(hdr, hdr_count, "folder");
    int col_type = find_col(hdr, hdr_count, "type");
    int col_name = find_col(hdr, hdr_count, "name");
    int col_notes = find_col(hdr, hdr_count, "notes");
    int col_uri = find_col(hdr, hdr_count, "login_uri");
    int col_username = find_col(hdr, hdr_count, "login_username");
    int col_password = find_col(hdr, hdr_count, "login_password");
    int col_totp = find_col(hdr, hdr_count, "login_totp");

    free_csv_fields(hdr, hdr_count);

    /* Process data rows */
    char **fields = NULL;
    int count = 0;
    int64_t now = (int64_t)time(NULL);

    while (csv_read_row(p, &fields, &count) == 1)
    {
        const char *type_val = get_field(fields, count, col_type);

        /* Skip non-login rows silently */
        if (strcmp(type_val, "login") != 0)
        {
            free_csv_fields(fields, count);
            continue;
        }

        const char *url = get_field(fields, count, col_uri);
        const char *username = get_field(fields, count, col_username);

        /* Duplicate detection: URL + username */
        if (is_duplicate(db, url, username))
        {
            result.skipped_duplicates++;
            free_csv_fields(fields, count);
            continue;
        }

        const char *folder = get_field(fields, count, col_folder);
        const char *totp = get_field(fields, count, col_totp);

        Entry e;
        memset(&e, 0, sizeof(e));
        uuid_generate(e.uuid);
        e.title = import_strdup(get_field(fields, count, col_name));
        e.url = import_strdup(url);
        e.username = import_strdup(username);
        e.password = import_strdup(get_field(fields, count, col_password));
        e.notes = import_strdup(get_field(fields, count, col_notes));
        e.totp_secret = import_strdup(totp[0] != '\0' ? totp : NULL);
        e.category = import_strdup(folder[0] != '\0' ? folder : "General");
        e.source = import_strdup("bitwarden");
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
        free(e.totp_secret);
        free(e.category);
        free(e.source);
        free_csv_fields(fields, count);
    }

    csv_close(p);
    return result;
}
