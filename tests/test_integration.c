/*
 * VaultC — Integration Test (Phase 8.2)
 * File: tests/test_integration.c
 *
 * Exercises the full session → vault → db → import → pwgen pipeline.
 * Runs headlessly (no GTK main loop required).
 */

#include "harness.h"
#include "vaultc/types.h"
#include "vaultc/crypto.h"
#include "vaultc/session.h"
#include "vaultc/db.h"
#include "vaultc/importer.h"
#include "vaultc/pwgen.h"
#include "vaultc/utils.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Helpers ───────────────────────────────────────────────────────────────── */

static char g_test_dir[512];
static char g_test_vault_path[512];

static void set_test_vault_env(void)
{
    /* Use a GLib temp dir so we don't pollute the real user data dir */
    char *tmpdir = g_dir_make_tmp("vaultc_integration_XXXXXX", NULL);
    ASSERT_NOT_NULL(tmpdir);

    snprintf(g_test_dir, sizeof(g_test_dir), "%s", tmpdir);
    snprintf(g_test_vault_path, sizeof(g_test_vault_path),
             "%s/vaultc/vault.vcf", tmpdir);

    /* Create the vaultc subdir */
    char vaultc_dir[512];
    snprintf(vaultc_dir, sizeof(vaultc_dir), "%s/vaultc", tmpdir);
    g_mkdir_with_parents(vaultc_dir, 0700);

    /* Set XDG_DATA_HOME so session_get_vault_path() uses our temp dir */
    g_setenv("XDG_DATA_HOME", tmpdir, TRUE);
    g_free(tmpdir);
}

static void cleanup_test_vault(void)
{
    session_lock();
    if (g_test_vault_path[0] != '\0')
    {
        g_unlink(g_test_vault_path);
    }
}

/* ── Test 1: Create new vault, add 3 entries, close, reopen — entries present */

TEST(test_create_add_close_reopen)
{
    ASSERT_EQ(crypto_init(), VAULTC_OK);
    set_test_vault_env();

    /* 1. Create vault */
    VaultcError err = session_create_vault("TestMaster123!");
    ASSERT_EQ(err, VAULTC_OK);
    ASSERT_FALSE(g_session.is_locked);

    /* 2. Add 3 entries */
    Entry e1 = {0};
    uuid_generate(e1.uuid);
    e1.title = "GitHub";
    e1.url = "https://github.com";
    e1.username = "alice";
    e1.password = "gh-pass-1234";
    e1.category = "Development";
    e1.source = "manual";
    e1.created_at = 1700000000;
    e1.updated_at = 1700000000;
    ASSERT_EQ(session_entry_create(&e1), VAULTC_OK);

    Entry e2 = {0};
    uuid_generate(e2.uuid);
    e2.title = "Gmail";
    e2.url = "https://mail.google.com";
    e2.username = "alice@gmail.com";
    e2.password = "gmail-secret-5678";
    e2.category = "Email";
    e2.source = "manual";
    e2.created_at = 1700000001;
    e2.updated_at = 1700000001;
    ASSERT_EQ(session_entry_create(&e2), VAULTC_OK);

    Entry e3 = {0};
    uuid_generate(e3.uuid);
    e3.title = "Netflix";
    e3.url = "https://netflix.com";
    e3.username = "alice";
    e3.password = "netflix-pw-9012";
    e3.category = "Entertainment";
    e3.source = "manual";
    e3.created_at = 1700000002;
    e3.updated_at = 1700000002;
    ASSERT_EQ(session_entry_create(&e3), VAULTC_OK);

    /* Verify 3 entries exist */
    EntryList *list = session_entry_list(NULL);
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, 3);
    db_free_entry_list(list);

    /* 3. Close (lock) the vault */
    session_lock();
    ASSERT_TRUE(g_session.is_locked);
    ASSERT_NULL(g_session.vault);

    /* 4. Reopen with correct password */
    err = session_open_vault("TestMaster123!");
    ASSERT_EQ(err, VAULTC_OK);
    ASSERT_FALSE(g_session.is_locked);

    /* 5. Verify all 3 entries are still present */
    list = session_entry_list(NULL);
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, 3);

    /* Verify entry content */
    int found_github = 0, found_gmail = 0, found_netflix = 0;
    for (size_t i = 0; i < list->count; i++)
    {
        if (strcmp(list->items[i]->title, "GitHub") == 0)
        {
            found_github = 1;
        }
        if (strcmp(list->items[i]->title, "Gmail") == 0)
        {
            found_gmail = 1;
        }
        if (strcmp(list->items[i]->title, "Netflix") == 0)
        {
            found_netflix = 1;
        }
    }
    ASSERT_TRUE(found_github);
    ASSERT_TRUE(found_gmail);
    ASSERT_TRUE(found_netflix);

    db_free_entry_list(list);
    cleanup_test_vault();
}

/* ── Test 2: Wrong master password shows error ─────────────────────────────── */

TEST(test_wrong_password_rejected)
{
    set_test_vault_env();

    /* Create vault */
    VaultcError err = session_create_vault("CorrectPassword!");
    ASSERT_EQ(err, VAULTC_OK);
    session_lock();

    /* Try wrong password */
    err = session_open_vault("WrongPassword!");
    ASSERT_EQ(err, VAULTC_ERR_BAD_PASSWORD);
    ASSERT_TRUE(g_session.is_locked);
    ASSERT_NULL(g_session.vault);

    /* Try correct password */
    err = session_open_vault("CorrectPassword!");
    ASSERT_EQ(err, VAULTC_OK);
    ASSERT_FALSE(g_session.is_locked);

    cleanup_test_vault();
}

/* ── Test 3: Import Google CSV, verify entry count ─────────────────────────── */

TEST(test_import_google_csv_count)
{
    set_test_vault_env();

    VaultcError err = session_create_vault("ImportTest123!");
    ASSERT_EQ(err, VAULTC_OK);

    void *db = session_get_db();
    ASSERT_NOT_NULL(db);

    ImportResult result = import_google_csv(db, FIXTURES_DIR "/google_sample.csv");
    ASSERT_EQ(result.imported, 3);
    ASSERT_EQ(result.errors, 0);

    /* Save after import */
    ASSERT_EQ(session_save(), VAULTC_OK);

    /* Verify entries in list */
    EntryList *list = session_entry_list(NULL);
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, 3);
    db_free_entry_list(list);

    cleanup_test_vault();
}

/* ── Test 4: Import same CSV again, duplicates skipped ─────────────────────── */

TEST(test_import_duplicates_skipped)
{
    set_test_vault_env();

    VaultcError err = session_create_vault("DupTest123!");
    ASSERT_EQ(err, VAULTC_OK);

    void *db = session_get_db();
    ASSERT_NOT_NULL(db);

    /* First import */
    ImportResult r1 = import_google_csv(db, FIXTURES_DIR "/google_sample.csv");
    ASSERT_EQ(r1.imported, 3);

    /* Second import — same CSV */
    ImportResult r2 = import_google_csv(db, FIXTURES_DIR "/google_sample.csv");
    ASSERT_EQ(r2.imported, 0);
    ASSERT_EQ(r2.skipped_duplicates, 3);

    /* Total entries should still be 3 */
    EntryList *list = session_entry_list(NULL);
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, 3);
    db_free_entry_list(list);

    cleanup_test_vault();
}

/* ── Test 5: Password generator produces correct output ────────────────────── */

TEST(test_generator_correct_output)
{
    PwgenOptions opts = {
        .length = 24,
        .use_uppercase = 1,
        .use_lowercase = 1,
        .use_digits = 1,
        .use_symbols = 1,
        .exclude_chars = NULL,
        .min_uppercase = 2,
        .min_digits = 2,
        .min_symbols = 1,
    };

    char *pw = pwgen_generate(&opts);
    ASSERT_NOT_NULL(pw);
    ASSERT_EQ((int)strlen(pw), 24);

    /* Verify minimum constraints met */
    int upper = 0, digit = 0, symbol = 0;
    for (int i = 0; i < 24; i++)
    {
        if (pw[i] >= 'A' && pw[i] <= 'Z')
            upper++;
        if (pw[i] >= '0' && pw[i] <= '9')
            digit++;
        if (!(pw[i] >= 'a' && pw[i] <= 'z') &&
            !(pw[i] >= 'A' && pw[i] <= 'Z') &&
            !(pw[i] >= '0' && pw[i] <= '9'))
        {
            symbol++;
        }
    }
    ASSERT_TRUE(upper >= 2);
    ASSERT_TRUE(digit >= 2);
    ASSERT_TRUE(symbol >= 1);

    /* Strength should be strong or very strong */
    StrengthScore score = pwgen_check_strength(pw);
    ASSERT_TRUE(score >= STRENGTH_STRONG);

    crypto_secure_zero(pw, (size_t)opts.length);
    free(pw);
}

/* ── Test 6: Lock/unlock cycle ─────────────────────────────────────────────── */

TEST(test_lock_unlock_cycle)
{
    set_test_vault_env();

    VaultcError err = session_create_vault("LockTest123!");
    ASSERT_EQ(err, VAULTC_OK);
    ASSERT_FALSE(g_session.is_locked);

    /* Add an entry */
    Entry e = {0};
    uuid_generate(e.uuid);
    e.title = "LockTest";
    e.url = "https://example.com";
    e.username = "user";
    e.password = "pass";
    e.category = "General";
    e.source = "manual";
    e.created_at = 1700000000;
    e.updated_at = 1700000000;
    ASSERT_EQ(session_entry_create(&e), VAULTC_OK);

    /* Lock */
    session_lock();
    ASSERT_TRUE(g_session.is_locked);
    ASSERT_NULL(session_get_db());

    /* Operations should fail while locked */
    EntryList *list = session_entry_list(NULL);
    ASSERT_NULL(list);

    /* Unlock */
    err = session_open_vault("LockTest123!");
    ASSERT_EQ(err, VAULTC_OK);
    ASSERT_FALSE(g_session.is_locked);

    /* Entry should be there */
    list = session_entry_list(NULL);
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, 1);
    ASSERT_STR_EQ(list->items[0]->title, "LockTest");
    db_free_entry_list(list);

    cleanup_test_vault();
}

/* ── Test 7: Change master password ────────────────────────────────────────── */

TEST(test_change_master_password)
{
    set_test_vault_env();

    VaultcError err = session_create_vault("OldPassword!");
    ASSERT_EQ(err, VAULTC_OK);

    /* Add entry for persistence check */
    Entry e = {0};
    uuid_generate(e.uuid);
    e.title = "PwChangeTest";
    e.url = "https://example.com";
    e.username = "bob";
    e.password = "secret";
    e.category = "General";
    e.source = "manual";
    e.created_at = 1700000000;
    e.updated_at = 1700000000;
    ASSERT_EQ(session_entry_create(&e), VAULTC_OK);

    /* Change password */
    err = session_change_password("OldPassword!", "NewPassword!");
    ASSERT_EQ(err, VAULTC_OK);

    /* Lock and try old password — should fail */
    session_lock();
    err = session_open_vault("OldPassword!");
    ASSERT_EQ(err, VAULTC_ERR_BAD_PASSWORD);

    /* Try new password — should succeed */
    err = session_open_vault("NewPassword!");
    ASSERT_EQ(err, VAULTC_OK);

    /* Entry should be intact */
    EntryList *list = session_entry_list(NULL);
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, 1);
    ASSERT_STR_EQ(list->items[0]->title, "PwChangeTest");
    db_free_entry_list(list);

    cleanup_test_vault();
}

/* ── Test 8: Entry CRUD lifecycle through session ──────────────────────────── */

TEST(test_entry_crud_lifecycle)
{
    set_test_vault_env();

    VaultcError err = session_create_vault("CRUDTest123!");
    ASSERT_EQ(err, VAULTC_OK);

    /* Create */
    Entry e = {0};
    uuid_generate(e.uuid);
    char uuid_copy[VAULTC_UUID_LEN];
    strncpy(uuid_copy, e.uuid, VAULTC_UUID_LEN);
    e.title = "CRUDEntry";
    e.url = "https://crud.example.com";
    e.username = "crud_user";
    e.password = "crud_pass";
    e.category = "Testing";
    e.source = "manual";
    e.created_at = 1700000000;
    e.updated_at = 1700000000;
    ASSERT_EQ(session_entry_create(&e), VAULTC_OK);

    /* Read back */
    void *db = session_get_db();
    Entry *read = db_entry_read(db, uuid_copy);
    ASSERT_NOT_NULL(read);
    ASSERT_STR_EQ(read->title, "CRUDEntry");
    ASSERT_STR_EQ(read->password, "crud_pass");
    db_free_entry(read);

    /* Update */
    Entry e_upd = {0};
    strncpy(e_upd.uuid, uuid_copy, VAULTC_UUID_LEN);
    e_upd.title = "UpdatedEntry";
    e_upd.url = "https://updated.example.com";
    e_upd.username = "updated_user";
    e_upd.password = "updated_pass";
    e_upd.category = "Updated";
    e_upd.source = "manual";
    e_upd.created_at = 1700000000;
    e_upd.updated_at = 1700000100;
    ASSERT_EQ(session_entry_update(&e_upd), VAULTC_OK);

    read = db_entry_read(db, uuid_copy);
    ASSERT_NOT_NULL(read);
    ASSERT_STR_EQ(read->title, "UpdatedEntry");
    ASSERT_STR_EQ(read->password, "updated_pass");
    db_free_entry(read);

    /* Delete */
    ASSERT_EQ(session_entry_delete(uuid_copy), VAULTC_OK);

    read = db_entry_read(db, uuid_copy);
    ASSERT_NULL(read);

    cleanup_test_vault();
}

/* ── Test 9: Import all 4 formats ──────────────────────────────────────────── */

TEST(test_import_all_formats)
{
    set_test_vault_env();

    VaultcError err = session_create_vault("AllFormats123!");
    ASSERT_EQ(err, VAULTC_OK);

    void *db = session_get_db();

    /* Google */
    ImportResult r1 = import_google_csv(db, FIXTURES_DIR "/google_sample.csv");
    ASSERT_EQ(r1.errors, 0);
    ASSERT_TRUE(r1.imported > 0);

    /* Firefox */
    ImportResult r2 = import_firefox_csv(db, FIXTURES_DIR "/firefox_sample.csv");
    ASSERT_EQ(r2.errors, 0);

    /* iOS */
    ImportResult r3 = import_ios_csv(db, FIXTURES_DIR "/ios_sample.csv");
    ASSERT_EQ(r3.errors, 0);

    /* Bitwarden */
    ImportResult r4 = import_bitwarden_csv(db, FIXTURES_DIR "/bitwarden_sample.csv");
    ASSERT_EQ(r4.errors, 0);

    int total = r1.imported + r2.imported + r3.imported + r4.imported;
    ASSERT_TRUE(total > 0);

    /* Save and verify persistence */
    ASSERT_EQ(session_save(), VAULTC_OK);
    session_lock();

    err = session_open_vault("AllFormats123!");
    ASSERT_EQ(err, VAULTC_OK);

    EntryList *list = session_entry_list(NULL);
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, total);
    db_free_entry_list(list);

    cleanup_test_vault();
}

/* ── Test 10: Search functionality ─────────────────────────────────────────── */

TEST(test_search_entries)
{
    set_test_vault_env();

    VaultcError err = session_create_vault("SearchTest123!");
    ASSERT_EQ(err, VAULTC_OK);

    /* Add entries with distinct names */
    const char *titles[] = {"GitHub", "GitLab", "Gmail", "Netflix"};
    for (int i = 0; i < 4; i++)
    {
        Entry e = {0};
        uuid_generate(e.uuid);
        e.title = (char *)titles[i];
        e.url = "https://example.com";
        e.username = "user";
        e.password = "pass";
        e.category = "General";
        e.source = "manual";
        e.created_at = 1700000000 + i;
        e.updated_at = 1700000000 + i;
        ASSERT_EQ(session_entry_create(&e), VAULTC_OK);
    }

    /* Search for "Git" — should find 2 */
    EntryList *list = session_entry_search("Git");
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, 2);
    db_free_entry_list(list);

    /* Search for "Netflix" — should find 1 */
    list = session_entry_search("Netflix");
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, 1);
    db_free_entry_list(list);

    /* Search for nonexistent — should find 0 */
    list = session_entry_search("ZZZNonExistent");
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, 0);
    db_free_entry_list(list);

    cleanup_test_vault();
}

/* ── Runner ────────────────────────────────────────────────────────────────── */

int main(void)
{
    RUN_TEST(test_create_add_close_reopen);
    RUN_TEST(test_wrong_password_rejected);
    RUN_TEST(test_import_google_csv_count);
    RUN_TEST(test_import_duplicates_skipped);
    RUN_TEST(test_generator_correct_output);
    RUN_TEST(test_lock_unlock_cycle);
    RUN_TEST(test_change_master_password);
    RUN_TEST(test_entry_crud_lifecycle);
    RUN_TEST(test_import_all_formats);
    RUN_TEST(test_search_entries);
    PRINT_RESULTS();
    return g_tests_failed > 0 ? 1 : 0;
}
