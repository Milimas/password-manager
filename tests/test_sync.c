/*
 * VaultC — Sync Module Tests
 * File: tests/test_sync.c
 *
 * Exercises configuration load/save and basic no-op behaviour when no
 * configuration exists.  Real network operations are not performed in the
 * unit tests.
 */

#include "harness.h"
#include "vaultc/sync.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>

static void set_test_env(void)
{
    /* create temporary XDG_DATA_HOME */
    char *tmpdir = g_dir_make_tmp("/tmp/vaultc-test-XXXXXX", NULL);
    if (tmpdir == NULL)
        return;
    g_setenv("XDG_DATA_HOME", tmpdir, TRUE);
    /* flush GLib cache so g_get_user_data_dir() picks up new value */
    (void)g_get_user_data_dir();
    g_free(tmpdir);
}

void test_no_config(void)
{
    /* use an isolated temp directory so no config file exists */
    set_test_env();
    SyncConfig *cfg = sync_config_load();
    if (cfg != NULL)
        sync_config_free(cfg);
    ASSERT_NULL(cfg);
    ASSERT_EQ(sync_upload("/does/not/exist", NULL), VAULTC_OK);
    ASSERT_EQ(sync_download("/does/not/exist", NULL), VAULTC_OK);
    ASSERT_EQ(sync_get_remote_mtime(NULL, NULL), VAULTC_OK);
}

void test_config_roundtrip(void)
{
    set_test_env();

    /* wipe any existing config in both the cached user data directory and
       the directory referenced by the new XDG_DATA_HOME value */
    char *p = g_build_filename(g_get_user_data_dir(), "vaultc", "sync.conf", NULL);
    g_unlink(p);
    g_free(p);
    const char *xdg = g_getenv("XDG_DATA_HOME");
    if (xdg != NULL)
    {
        char *q = g_build_filename(xdg, "vaultc", "sync.conf", NULL);
        g_unlink(q);
        g_free(q);
    }

    SyncConfig cfg = {0};
    cfg.endpoint = g_strdup("https://example.com");
    cfg.bucket = g_strdup("mybucket");
    cfg.access_key_id = g_strdup("AKIA_TEST");
    cfg.secret_access_key = g_strdup("SECRET123");
    cfg.object_key = g_strdup("vault.vcf");
    cfg.enabled = 1;

    ASSERT_EQ(sync_config_save(&cfg), VAULTC_OK);

    SyncConfig *cfg2 = sync_config_load();
    ASSERT_NOT_NULL(cfg2);
    ASSERT_STR_EQ(cfg2->endpoint, cfg.endpoint);
    ASSERT_STR_EQ(cfg2->bucket, cfg.bucket);
    ASSERT_STR_EQ(cfg2->access_key_id, cfg.access_key_id);
    ASSERT_STR_EQ(cfg2->secret_access_key, cfg.secret_access_key);
    ASSERT_STR_EQ(cfg2->object_key, cfg.object_key);
    ASSERT_TRUE(cfg2->enabled == cfg.enabled);

    sync_config_free(cfg2);

    /* free local copies */
    g_free(cfg.endpoint);
    g_free(cfg.bucket);
    g_free(cfg.access_key_id);
    g_free(cfg.secret_access_key);
    g_free(cfg.object_key);
}

void test_clear_on_stack(void)
{
    SyncConfig cfg = {0};
    cfg.endpoint = g_strdup("foo");
    cfg.bucket   = g_strdup("bar");
    sync_config_clear(&cfg);
    ASSERT_NULL(cfg.endpoint);
    ASSERT_NULL(cfg.bucket);
}

int main(void)
{
    RUN_TEST(test_no_config);
    RUN_TEST(test_config_roundtrip);
    RUN_TEST(test_clear_on_stack);
    return 0;
}
