/*
 * VaultC — iOS CSV Importer
 * File: src/import/import_ios.c
 *
 * iOS CSV columns: Title, URL, Username, Password, Notes, OTPAuth
 */

#include "vaultc/importer.h"
#include "import_helpers.h"

/* ── Internal: extract secret= value from otpauth:// URI ───────────────────── */

static char *extract_totp_secret(const char *otpauth_uri)
{
    if (otpauth_uri == NULL || otpauth_uri[0] == '\0')
    {
        return NULL;
    }

    /* Look for "secret=" parameter (case-insensitive) */
    const char *search = otpauth_uri;
    const char *found = NULL;

    while (*search != '\0')
    {
        if ((*search == 's' || *search == 'S') &&
            strncmp(search, "secret=", 7) == 0)
        {
            found = search + 7;
            break;
        }
        if ((*search == 'S') &&
            strncmp(search, "SECRET=", 7) == 0)
        {
            found = search + 7;
            break;
        }
        search++;
    }

    if (found == NULL)
    {
        return NULL;
    }

    /* Read until '&' or end of string */
    const char *end = found;
    while (*end != '\0' && *end != '&')
    {
        end++;
    }

    size_t len = (size_t)(end - found);
    if (len == 0)
    {
        return NULL;
    }

    char *secret = malloc(len + 1);
    if (secret == NULL)
    {
        abort();
    }
    memcpy(secret, found, len);
    secret[len] = '\0';

    return secret;
}

ImportResult import_ios_csv(void *db, const char *path)
{
    ImportResult result = {0, 0, 0, NULL, IMPORT_IOS};

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

    int col_title = find_col(hdr, hdr_count, "Title");
    int col_url = find_col(hdr, hdr_count, "URL");
    int col_username = find_col(hdr, hdr_count, "Username");
    int col_password = find_col(hdr, hdr_count, "Password");
    int col_notes = find_col(hdr, hdr_count, "Notes");
    int col_otp = find_col(hdr, hdr_count, "OTPAuth");

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

        const char *otp_raw = get_field(fields, count, col_otp);

        Entry e;
        memset(&e, 0, sizeof(e));
        uuid_generate(e.uuid);
        e.title = import_strdup(get_field(fields, count, col_title));
        e.url = import_strdup(url);
        e.username = import_strdup(username);
        e.password = import_strdup(get_field(fields, count, col_password));
        e.notes = import_strdup(get_field(fields, count, col_notes));
        e.totp_secret = extract_totp_secret(otp_raw);
        e.category = import_strdup("General");
        e.source = import_strdup("ios");
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
