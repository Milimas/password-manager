/*
 * VaultC — Cloud Sync (Cloudflare R2)
 * File: include/vaultc/sync.h
 *
 * Provides an optional synchronization layer that uploads the encrypted
 * vault file to Cloudflare R2 and downloads updates.  Configuration is
 * stored in a small INI file under ~/.local/share/vaultc/sync.conf; the
 * sync code never touches the vault contents directly (it merely copies
 * the .vcf file as-is).
 */

#ifndef VAULTC_SYNC_H
#define VAULTC_SYNC_H

#include "vaultc/types.h"
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Configuration for R2 sync.  All strings are heap-allocated and must be
 * freed with sync_config_free().
 */
typedef struct
{
    char *endpoint;          /**< Base URL (e.g. https://<acct>.r2.cloudflarestorage.com) */
    char *bucket;            /**< Bucket name */
    char *access_key_id;     /**< AWS access key ID */
    char *secret_access_key; /**< AWS secret access key */
    char *object_key;        /**< Object name within bucket (typically "vault.vcf") */
    int    enabled;          /**< 1 to enable sync, 0 to disable */
} SyncConfig;

/**
 * Load the sync configuration from disk.
 * @return Heap-allocated SyncConfig, or NULL if no config exists or load
 *         failed.  Caller must free with sync_config_free().
 */
SyncConfig *sync_config_load(void);

/**
 * Save a configuration to disk, creating parent directories as needed.
 * @return VAULTC_OK on success, or an error code.
 */
VaultcError sync_config_save(const SyncConfig *cfg);

/**
 * Free a SyncConfig previously returned by sync_config_load().
 */
void sync_config_free(SyncConfig *cfg);

/**
 * Free only the string fields of a SyncConfig.  Does **not** free the
 * struct pointer itself.  Useful when the config is stack-allocated.
 */
void sync_config_clear(SyncConfig *cfg);

/**
 * Query the remote object's modification time without downloading it.
 * @param cfg       Configuration (may be NULL or disabled).
 * @param mtime_out If non-NULL receives the Unix timestamp; zero if
 *                  object does not exist or time is unavailable.
 * @return VAULTC_OK on success, VAULTC_ERR_NETWORK on network failure,
 *         VAULTC_ERR_INVALID_ARG for missing fields.
 */
VaultcError sync_get_remote_mtime(const SyncConfig *cfg, time_t *mtime_out);

/**
 * Upload the vault file to R2.  Existing object will be overwritten.
 * @param vault_path  Path to local .vcf file.
 * @param cfg         Configuration (may be NULL or disabled).
 * @return VAULTC_OK on success or if sync is disabled, otherwise an error.
 */
VaultcError sync_upload(const char *vault_path, const SyncConfig *cfg);

/**
 * Download the remote vault file if it is newer than the local copy.
 * @param vault_path  Path to local .vcf file (will be overwritten).
 * @param cfg         Configuration (may be NULL or disabled).
 * @return VAULTC_OK on success or if no action required, otherwise an error.
 */
VaultcError sync_download(const char *vault_path, const SyncConfig *cfg);

#ifdef __cplusplus
}
#endif

#endif /* VAULTC_SYNC_H */
