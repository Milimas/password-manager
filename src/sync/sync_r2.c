/*
 * VaultC — Cloud Sync (Cloudflare R2)
 * File: src/sync/sync_r2.c
 *
 * Implements optional upload/download of the encrypted vault file using the
 * S3-compatible API provided by Cloudflare R2.  Communication is performed
 * with libcurl when available; if curl is not present all functions are
 * no-ops so the rest of the codebase can call them unconditionally.
 */

#include "vaultc/sync.h"
#include "vaultc/crypto.h"
#include <glib.h>
#include <glib/gstdio.h>
#include <sys/stat.h>
#include <time.h>

#ifdef HAVE_LIBCURL
#include <curl/curl.h>
#include <sodium/crypto_hash_sha256.h>
#endif

/* helper to construct path to sync.conf */
static char *get_sync_config_path(void)
{
    const char *data = g_get_user_data_dir();
    return g_build_filename(data, "vaultc", "sync.conf", NULL);
}

SyncConfig *sync_config_load(void)
{
    char *path = get_sync_config_path();
    /* load sync config if present */
    if (!g_file_test(path, G_FILE_TEST_EXISTS))
    {
        g_free(path);
        return NULL;
    }

    GKeyFile *kf = g_key_file_new();
    GError *err = NULL;
    if (!g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, &err))
    {
        g_key_file_free(kf);
        g_free(path);
        return NULL;
    }

    SyncConfig *cfg = g_new0(SyncConfig, 1);
    cfg->endpoint = g_key_file_get_string(kf, "sync", "endpoint", NULL);
    cfg->bucket = g_key_file_get_string(kf, "sync", "bucket", NULL);
    cfg->access_key_id = g_key_file_get_string(kf, "sync", "access_key_id", NULL);
    cfg->secret_access_key = g_key_file_get_string(kf, "sync", "secret_access_key", NULL);
    cfg->object_key = g_key_file_get_string(kf, "sync", "object_key", NULL);
    cfg->enabled = g_key_file_get_boolean(kf, "sync", "enabled", NULL);

    g_key_file_free(kf);
    g_free(path);
    return cfg;
}

VaultcError sync_config_save(const SyncConfig *cfg)
{
    if (cfg == NULL)
        return VAULTC_ERR_INVALID_ARG;

    char *path = get_sync_config_path();
    char *dir = g_path_get_dirname(path);
    g_mkdir_with_parents(dir, 0700);
    g_free(dir);

    GKeyFile *kf = g_key_file_new();
    g_key_file_set_string(kf, "sync", "endpoint", cfg->endpoint ? cfg->endpoint : "");
    g_key_file_set_string(kf, "sync", "bucket", cfg->bucket ? cfg->bucket : "");
    g_key_file_set_string(kf, "sync", "access_key_id", cfg->access_key_id ? cfg->access_key_id : "");
    g_key_file_set_string(kf, "sync", "secret_access_key", cfg->secret_access_key ? cfg->secret_access_key : "");
    g_key_file_set_string(kf, "sync", "object_key", cfg->object_key ? cfg->object_key : "");
    g_key_file_set_boolean(kf, "sync", "enabled", cfg->enabled);

    GError *err = NULL;
    gchar *data = g_key_file_to_data(kf, NULL, NULL);
    if (!g_file_set_contents(path, data, -1, &err))
    {
        g_free(data);
        g_key_file_free(kf);
        g_free(path);
        return VAULTC_ERR_IO;
    }

    /* restrict file permissions to owner only */
    g_chmod(path, 0600);

    g_free(data);
    g_key_file_free(kf);
    g_free(path);
    return VAULTC_OK;
}

void sync_config_clear(SyncConfig *cfg)
{
    if (cfg == NULL)
        return;
    g_free(cfg->endpoint);
    g_free(cfg->bucket);
    g_free(cfg->access_key_id);
    g_free(cfg->secret_access_key);
    g_free(cfg->object_key);
    cfg->endpoint = cfg->bucket = cfg->access_key_id =
        cfg->secret_access_key = cfg->object_key = NULL;
}

void sync_config_free(SyncConfig *cfg)
{
    if (cfg == NULL)
        return;
    sync_config_clear(cfg);
    g_free(cfg);
}

#ifdef HAVE_LIBCURL
VaultcError sync_get_remote_mtime(const SyncConfig *cfg, time_t *mtime_out)
{
    if (mtime_out)
        *mtime_out = 0;

    if (cfg == NULL || !cfg->enabled)
        return VAULTC_OK;

    if (!cfg->endpoint || !cfg->bucket || !cfg->access_key_id || !cfg->secret_access_key || !cfg->object_key)
        return VAULTC_ERR_INVALID_ARG;

    CURL *curl = curl_easy_init();
    if (!curl)
        return VAULTC_ERR_NETWORK;

    /* Insert bucket name between scheme and host.
       endpoint is "https://ACCOUNTID.r2.cloudflarestorage.com"
       target is   "https://BUCKET.ACCOUNTID.r2.cloudflarestorage.com/OBJECT" */
    const char *scheme_end = strstr(cfg->endpoint, "://");
    char *url;
    if (scheme_end) {
        char *scheme = g_strndup(cfg->endpoint,
                                 (scheme_end + 3) - cfg->endpoint);
        url = g_strdup_printf("%s%s.%s/%s",
                              scheme,
                              cfg->bucket,
                              scheme_end + 3,
                              cfg->object_key);
        g_free(scheme);
    } else {
        url = g_strdup_printf("%s/%s/%s",
                              cfg->endpoint, cfg->bucket, cfg->object_key);
    }

    char *userpwd = g_strdup_printf("%s:%s",
                                   cfg->access_key_id,
                                   cfg->secret_access_key);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd);
    curl_easy_setopt(curl, CURLOPT_AWS_SIGV4, "aws:amz:auto:s3");
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
    /* verbose logging disabled in release builds */

    CURLcode res = curl_easy_perform(curl);
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    curl_off_t filetime = -1;
    curl_easy_getinfo(curl, CURLINFO_FILETIME_T, &filetime);

    /* wipe credentials */
    if (userpwd) {
        crypto_secure_zero(userpwd, strlen(userpwd));
        g_free(userpwd);
    }
    curl_easy_cleanup(curl);
    g_free(url);

    if (res != CURLE_OK)
        return VAULTC_ERR_NETWORK;

    if (response_code == 404)
    {
        if (mtime_out)
            *mtime_out = 0;
        return VAULTC_OK;
    }

    if (response_code < 200 || response_code >= 300)
        return VAULTC_ERR_NETWORK;

    if (mtime_out)
        *mtime_out = (filetime != -1) ? (time_t)filetime : 0;
    return VAULTC_OK;
#else
    (void)cfg;
    return VAULTC_OK;
#endif
}

VaultcError sync_upload(const char *vault_path, const SyncConfig *cfg)
{
    /* upload requested (background task will perform network I/O) */

    if (cfg == NULL || !cfg->enabled)
        return VAULTC_OK;

#ifdef HAVE_LIBCURL
    if (!vault_path || !cfg->endpoint || !cfg->bucket ||
        !cfg->access_key_id || !cfg->secret_access_key || !cfg->object_key)
        return VAULTC_ERR_INVALID_ARG;

    struct stat st;
    if (stat(vault_path, &st) != 0)
        return VAULTC_ERR_IO;

    FILE *fp = fopen(vault_path, "rb");
    if (!fp)
        return VAULTC_ERR_IO;

    CURL *curl = curl_easy_init();
    if (!curl)
    {
        fclose(fp);
        return VAULTC_ERR_NETWORK;
    }

    /* Insert bucket into hostname (virtual-hosted-style) */
    const char *scheme_end = strstr(cfg->endpoint, "://");
    char *url;
    if (scheme_end) {
        char *scheme = g_strndup(cfg->endpoint,
                                 (scheme_end + 3) - cfg->endpoint);
        url = g_strdup_printf("%s%s.%s/%s",
                              scheme,
                              cfg->bucket,
                              scheme_end + 3,
                              cfg->object_key);
        g_free(scheme);
    } else {
        url = g_strdup_printf("%s/%s/%s",
                              cfg->endpoint, cfg->bucket, cfg->object_key);
    }
    char *userpwd = g_strdup_printf("%s:%s",
                                   cfg->access_key_id,
                                   cfg->secret_access_key);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd);
    curl_easy_setopt(curl, CURLOPT_AWS_SIGV4, "aws:amz:auto:s3");
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_READDATA, fp);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)st.st_size);

    /* explicit content type header required by R2 */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");

    /* Do not compute x-amz-content-sha256 manually; let libcurl handle
     * SigV4-related payload hashing. Only set Content-Type here. */

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    /* perform completed; response_code contains HTTP result */

    /* wipe credentials before freeing */
    if (userpwd) {
        crypto_secure_zero(userpwd, strlen(userpwd));
        g_free(userpwd);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    fclose(fp);
    g_free(url);

    if (res != CURLE_OK)
        return VAULTC_ERR_NETWORK;
    if (response_code < 200 || response_code >= 300)
        return VAULTC_ERR_NETWORK;
    return VAULTC_OK;
#else
    (void)vault_path;
    (void)cfg;
    return VAULTC_OK;
#endif
}

VaultcError sync_download(const char *vault_path, const SyncConfig *cfg)
{
    if (cfg == NULL || !cfg->enabled)
        return VAULTC_OK;

#ifdef HAVE_LIBCURL
    if (!vault_path || !cfg->endpoint || !cfg->bucket ||
        !cfg->access_key_id || !cfg->secret_access_key || !cfg->object_key)
        return VAULTC_ERR_INVALID_ARG;

    /* determine remote modification time */
    time_t remote = 0;
    VaultcError err = sync_get_remote_mtime(cfg, &remote);
    if (err != VAULTC_OK || remote == 0)
        return VAULTC_OK; /* nothing to do or unable to query */

    struct stat st;
    if (stat(vault_path, &st) == 0 && remote <= st.st_mtime)
        return VAULTC_OK; /* local is newer or same */

    /* perform GET into temporary file */
    char *tmp = g_strconcat(vault_path, ".tmp", NULL);
    FILE *out = g_fopen(tmp, "wb");
    if (!out)
    {
        g_free(tmp);
        return VAULTC_ERR_IO;
    }

    CURL *curl = curl_easy_init();
    if (!curl)
    {
        fclose(out);
        g_unlink(tmp);
        g_free(tmp);
        return VAULTC_ERR_NETWORK;
    }

    /* build URL and credentials */
    /* Insert bucket into hostname (virtual-hosted-style) */
    const char *scheme_end = strstr(cfg->endpoint, "://");
    char *url;
    if (scheme_end) {
        char *scheme = g_strndup(cfg->endpoint,
                                 (scheme_end + 3) - cfg->endpoint);
        url = g_strdup_printf("%s%s.%s/%s",
                              scheme,
                              cfg->bucket,
                              scheme_end + 3,
                              cfg->object_key);
        g_free(scheme);
    } else {
        url = g_strdup_printf("%s/%s/%s",
                              cfg->endpoint, cfg->bucket, cfg->object_key);
    }
    char *userpwd = g_strdup_printf("%s:%s",
                                   cfg->access_key_id,
                                   cfg->secret_access_key);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd);
    curl_easy_setopt(curl, CURLOPT_AWS_SIGV4, "aws:amz:auto:s3");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
    /* verbose logging disabled in release builds */

    /* headers not strictly necessary for GET, but include content-type */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    /* wipe and free credential string */
    crypto_secure_zero(userpwd, strlen(userpwd));
    g_free(userpwd);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    g_free(url);

    if (res != CURLE_OK || response_code < 200 || response_code >= 300)
    {
        g_unlink(tmp);
        g_free(tmp);
        return VAULTC_ERR_NETWORK;
    }

    /* replace original file atomically */
    if (g_rename(tmp, vault_path) != 0)
    {
        g_unlink(tmp);
        g_free(tmp);
        return VAULTC_ERR_IO;
    }

    g_free(tmp);
    return VAULTC_OK;
#else
    (void)vault_path;
    (void)cfg;
    return VAULTC_OK;
#endif
}
