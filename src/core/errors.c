/*
 * VaultC — Error Code String Conversion
 * File: src/core/errors.c
 */

#include "vaultc/types.h"

const char *vaultc_strerror(VaultcError err)
{
    switch (err)
    {
    case VAULTC_OK:
        return "Success";
    case VAULTC_ERR_IO:
        return "File I/O error";
    case VAULTC_ERR_CRYPTO:
        return "Cryptographic operation failed";
    case VAULTC_ERR_BAD_PASSWORD:
        return "Wrong master password";
    case VAULTC_ERR_CORRUPT:
        return "File is corrupt or invalid format";
    case VAULTC_ERR_NOMEM:
        return "Memory allocation failed";
    case VAULTC_ERR_INVALID_ARG:
        return "NULL or invalid argument passed";
    case VAULTC_ERR_DUPLICATE:
        return "Entry already exists";
    case VAULTC_ERR_NOT_FOUND:
        return "Entry not found";
    case VAULTC_ERR_DB:
        return "Database error";
    case VAULTC_ERR_TOO_LONG:
        return "String exceeds maximum length";
    default:
        return "Unknown error";
    }
}
