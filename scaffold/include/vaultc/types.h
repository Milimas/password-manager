/*
 * VaultC — Shared Type Definitions
 * File: include/vaultc/types.h
 */

#ifndef VAULTC_TYPES_H
#define VAULTC_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════
 * Error Codes
 * ═══════════════════════════════════════════════════════════════════════ */

typedef enum {
    VAULTC_OK               =  0,  /**< Operation succeeded */
    VAULTC_ERR_IO           = -1,  /**< File I/O error */
    VAULTC_ERR_CRYPTO       = -2,  /**< Cryptographic operation failed */
    VAULTC_ERR_BAD_PASSWORD = -3,  /**< Wrong master password */
    VAULTC_ERR_CORRUPT      = -4,  /**< File is corrupt or invalid format */
    VAULTC_ERR_NOMEM        = -5,  /**< Memory allocation failed */
    VAULTC_ERR_INVALID_ARG  = -6,  /**< NULL or invalid argument passed */
    VAULTC_ERR_DUPLICATE    = -7,  /**< Entry already exists (import) */
    VAULTC_ERR_NOT_FOUND    = -8,  /**< Entry not found */
    VAULTC_ERR_DB           = -9,  /**< SQLite error */
    VAULTC_ERR_TOO_LONG     = -10, /**< String exceeds maximum length */
} VaultcError;

/**
 * Returns a human-readable string for a VaultcError code.
 * The returned string is static — do not free it.
 */
const char *vaultc_strerror(VaultcError err);

/* ═══════════════════════════════════════════════════════════════════════
 * Import Format
 * ═══════════════════════════════════════════════════════════════════════ */

typedef enum {
    IMPORT_UNKNOWN   = 0,
    IMPORT_GOOGLE    = 1,
    IMPORT_FIREFOX   = 2,
    IMPORT_IOS       = 3,
    IMPORT_BITWARDEN = 4,
    IMPORT_LASTPASS  = 5,
    IMPORT_GENERIC   = 6,
} ImportFormat;

/* ═══════════════════════════════════════════════════════════════════════
 * Password Strength
 * ═══════════════════════════════════════════════════════════════════════ */

typedef enum {
    STRENGTH_VERY_WEAK  = 0,  /**< < 28 bits entropy  */
    STRENGTH_WEAK       = 1,  /**< 28-35 bits         */
    STRENGTH_FAIR       = 2,  /**< 36-59 bits         */
    STRENGTH_STRONG     = 3,  /**< 60-127 bits        */
    STRENGTH_VERY_STRONG= 4,  /**< 128+ bits          */
} StrengthScore;

/* ═══════════════════════════════════════════════════════════════════════
 * Entry — A single password record
 * ═══════════════════════════════════════════════════════════════════════ */

#define VAULTC_UUID_LEN      37   /* "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx\0" */
#define VAULTC_MAX_TITLE     256
#define VAULTC_MAX_URL       2048
#define VAULTC_MAX_USERNAME  256
#define VAULTC_MAX_PASSWORD  1024
#define VAULTC_MAX_NOTES     8192
#define VAULTC_MAX_CATEGORY  128
#define VAULTC_MAX_SOURCE    64

typedef struct Entry {
    char     uuid[VAULTC_UUID_LEN]; /**< RFC-4122 UUID, null-terminated       */
    char    *title;                 /**< Display name (heap-allocated)         */
    char    *url;                   /**< Website URL (heap-allocated, nullable)*/
    char    *username;              /**< Login username (heap-allocated)       */
    char    *password;              /**< Plaintext password — zero on free!    */
    char    *notes;                 /**< Free-form notes (nullable)            */
    char    *totp_secret;           /**< Base32 TOTP seed (nullable)           */
    char    *category;              /**< Folder/category name                  */
    char    *source;                /**< Import source or "manual"             */
    int      is_favorite;           /**< 1 if starred, 0 otherwise            */
    int64_t  created_at;            /**< Unix timestamp (seconds)              */
    int64_t  updated_at;            /**< Unix timestamp (seconds)              */
    int64_t  last_used;             /**< Unix timestamp, 0 if never            */
} Entry;

/* ═══════════════════════════════════════════════════════════════════════
 * EntryList — Dynamic array of Entry pointers
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    Entry  **items;    /**< Heap-allocated array of Entry pointers */
    size_t   count;    /**< Number of valid entries                */
    size_t   capacity; /**< Allocated capacity                     */
} EntryList;

/* ═══════════════════════════════════════════════════════════════════════
 * ImportResult — Summary of a completed import operation
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    int           imported;           /**< Number of entries successfully added */
    int           skipped_duplicates; /**< Skipped (already in vault)           */
    int           errors;             /**< Number of rows that failed to parse  */
    char        **error_messages;     /**< Array of error strings (nullable)    */
    ImportFormat  format_detected;    /**< Format that was detected/used        */
} ImportResult;

/* ═══════════════════════════════════════════════════════════════════════
 * PwgenOptions — Password generator configuration
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    int   length;          /**< Total password length (8–128)        */
    int   use_uppercase;   /**< Include A-Z                          */
    int   use_lowercase;   /**< Include a-z                          */
    int   use_digits;      /**< Include 0-9                          */
    int   use_symbols;     /**< Include !@#$%^&*...                  */
    char *exclude_chars;   /**< Characters to never include (nullable)*/
    int   min_uppercase;   /**< Minimum uppercase characters (>= 0)  */
    int   min_digits;      /**< Minimum digit characters (>= 0)      */
    int   min_symbols;     /**< Minimum symbol characters (>= 0)     */
} PwgenOptions;

/* ═══════════════════════════════════════════════════════════════════════
 * FilterOptions — Entry list filter/search parameters
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *search_query;  /**< Substring to match in title/url/username */
    const char *category;      /**< Filter to specific category (nullable)    */
    int         favorites_only;/**< 1 to show only favorites                  */
    const char *source;        /**< Filter by import source (nullable)        */
} FilterOptions;

#ifdef __cplusplus
}
#endif

#endif /* VAULTC_TYPES_H */
