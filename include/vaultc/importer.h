/*
 * VaultC — CSV Import Engine
 * File: include/vaultc/importer.h
 */

#ifndef VAULTC_IMPORTER_H
#define VAULTC_IMPORTER_H

#include <stdint.h>
#include <stddef.h>

#include "vaultc/types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /* ═══════════════════════════════════════════════════════════════════════
     * Format Detection
     * ═══════════════════════════════════════════════════════════════════════ */

    /**
     * Detect the import format of a CSV file by inspecting the header row.
     *
     * Matches column names only — never peeks at data rows.
     *
     * @param csv_path  Path to the CSV file.
     * @return          Detected ImportFormat enum value,
     *                  IMPORT_UNKNOWN if no match.
     */
    ImportFormat import_detect_format(const char *csv_path);

    /* ═══════════════════════════════════════════════════════════════════════
     * Format-Specific Importers
     * ═══════════════════════════════════════════════════════════════════════ */

    /**
     * Import entries from a Google Passwords CSV export.
     *
     * @param db   SQLite3 database handle (void* cast of sqlite3*).
     * @param path Path to the CSV file.
     * @return     ImportResult with counts of imported/skipped/errors.
     */
    ImportResult import_google_csv(void *db, const char *path);

    /**
     * Import entries from a Firefox Lockwise CSV export.
     *
     * @param db   SQLite3 database handle.
     * @param path Path to the CSV file.
     * @return     ImportResult with counts.
     */
    ImportResult import_firefox_csv(void *db, const char *path);

    /**
     * Import entries from an iOS/iCloud Keychain CSV export.
     *
     * Extracts TOTP secret from otpauth:// URIs if present.
     *
     * @param db   SQLite3 database handle.
     * @param path Path to the CSV file.
     * @return     ImportResult with counts.
     */
    ImportResult import_ios_csv(void *db, const char *path);

    /**
     * Import entries from a Bitwarden CSV export.
     *
     * Skips non-login rows (cards, identities, etc.) silently.
     *
     * @param db   SQLite3 database handle.
     * @param path Path to the CSV file.
     * @return     ImportResult with counts.
     */
    ImportResult import_bitwarden_csv(void *db, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* VAULTC_IMPORTER_H */
