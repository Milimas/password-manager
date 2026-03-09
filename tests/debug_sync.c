#include "vaultc/sync.h"
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int main(void)
{
    /* use a fresh XDG_DATA_HOME */
    char tmpdir[] = "/tmp/vaultc-debug-XXXXXX";
    if (g_mkdir_with_parents(g_mkdtemp(tmpdir), 0700) != 0) {
        perror("mkdtemp");
        return 1;
    }
    g_setenv("XDG_DATA_HOME", tmpdir, TRUE);

    /* copy .env file if it exists in repo root to the sync.conf location */
    char *cfgdir = g_build_filename(g_get_user_data_dir(), "vaultc", NULL);
    g_mkdir_with_parents(cfgdir, 0700);
    char *src = g_build_filename(g_get_current_dir(), ".env", NULL);
    char *dst = g_build_filename(cfgdir, "sync.conf", NULL);
    gchar *contents = NULL;
    gsize len = 0;
    if (g_file_get_contents(src, &contents, &len, NULL)) {
        g_file_set_contents(dst, contents, len, NULL);
        g_free(contents);
    }
    g_free(src);
    g_free(cfgdir);

    SyncConfig *cfg = sync_config_load();
    if (cfg == NULL) {
        fprintf(stderr, "no config loaded\n");
    } else {
        fprintf(stderr, "config loaded: endpoint=%s bucket=%s object=%s enabled=%d\n",
                cfg->endpoint, cfg->bucket, cfg->object_key, cfg->enabled);
    }

    /* create a dummy file to upload */
    const char *path = "dummy.txt";
    FILE *f = fopen(path, "w");
    if (f) {
        fputs("hello\n", f);
        fclose(f);
    }

    VaultcError r = sync_upload(path, cfg);
    fprintf(stderr, "sync_upload returned %d\n", r);

    if (cfg) sync_config_free(cfg);
    return 0;
}
