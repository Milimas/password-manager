/*
 * VaultC — Utility Functions (UUID, CSV, TOTP, Clipboard)
 * File: include/vaultc/utils.h
 */

#ifndef VAULTC_UTILS_H
#define VAULTC_UTILS_H

#include <stdint.h>
#include <stddef.h>

#include "vaultc/types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /* ═══════════════════════════════════════════════════════════════════════
     * UUID v4 Generation
     * ═══════════════════════════════════════════════════════════════════════ */

    /**
     * Generate a cryptographically random UUID v4 string.
     *
     * Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
     * Uses crypto_random_bytes for entropy.
     * Version nibble = 4, variant bits = 10xx (RFC 4122).
     *
     * @param out  Buffer of at least VAULTC_UUID_LEN (37) bytes.
     */
    void uuid_generate(char *out);

    /* ═══════════════════════════════════════════════════════════════════════
     * RFC 4180 CSV Parser
     * ═══════════════════════════════════════════════════════════════════════ */

    /** Opaque CSV parser handle. */
    typedef struct CsvParser CsvParser;

    /**
     * Open a CSV file for row-by-row reading.
     *
     * @param path  Path to the CSV file.
     * @return      Parser handle, or NULL on error.
     */
    CsvParser *csv_open(const char *path);

    /**
     * Read the next row from the CSV file.
     *
     * @param p          Parser handle.
     * @param fields_out Receives a heap-allocated array of field strings.
     *                   Caller must free each string and the array itself.
     * @param count_out  Receives the number of fields in this row.
     * @return           1 if a row was read, 0 on EOF, -1 on error.
     */
    int csv_read_row(CsvParser *p, char ***fields_out, int *count_out);

    /**
     * Close the CSV parser and free all resources.
     *
     * @param p  Parser handle. NULL is a safe no-op.
     */
    void csv_close(CsvParser *p);

    /* ═══════════════════════════════════════════════════════════════════════
     * TOTP (RFC 6238) — Time-based One-Time Password
     * ═══════════════════════════════════════════════════════════════════════ */

    /**
     * Generate a 6-digit TOTP code from a Base32-encoded secret.
     *
     * Uses HMAC-SHA1, 30-second time step, per RFC 6238.
     *
     * @param base32_secret  Null-terminated Base32-encoded secret.
     * @param out            Buffer of at least 7 bytes for the 6-digit code
     *                       (null-terminated).
     * @return               VAULTC_OK on success,
     *                       VAULTC_ERR_INVALID_ARG if inputs are NULL/empty.
     */
    VaultcError totp_generate(const char *base32_secret, char *out);

    /* ═══════════════════════════════════════════════════════════════════════
     * Clipboard (stubbed — GTK4 wiring in Phase 7)
     * ═══════════════════════════════════════════════════════════════════════ */

    /**
     * Copy text to the system clipboard.
     *
     * @param widget  Any GtkWidget in the active window (for display context).
     * @param text    Null-terminated string to copy.
     */
    void clipboard_set_text(void *widget, const char *text);

    /**
     * Schedule clipboard auto-clear after a delay.
     *
     * @param seconds  Number of seconds before clearing.
     */
    void clipboard_schedule_clear(int seconds);

    /**
     * Clear the clipboard immediately.
     */
    void clipboard_clear_now(void);

#ifdef __cplusplus
}
#endif

#endif /* VAULTC_UTILS_H */
