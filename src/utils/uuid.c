/*
 * VaultC — UUID v4 Generation
 * File: src/utils/uuid.c
 */

#include "vaultc/utils.h"

#include <stdio.h>

#include "vaultc/crypto.h"

/* ── UUID v4: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx ─────────────────────────── */

void uuid_generate(char *out)
{
    if (out == NULL)
    {
        return;
    }

    uint8_t bytes[16];
    crypto_random_bytes(bytes, sizeof(bytes));

    /* Set version nibble to 4 (bits 48-51 = 0100) */
    bytes[6] = (bytes[6] & 0x0F) | 0x40;

    /* Set variant bits to 10xx (bits 64-65) */
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    snprintf(out, VAULTC_UUID_LEN,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
             "%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5],
             bytes[6], bytes[7],
             bytes[8], bytes[9],
             bytes[10], bytes[11], bytes[12], bytes[13],
             bytes[14], bytes[15]);
}
