/*
 * VaultC — CSV Import Tests
 * File: tests/test_import.c
 */

#include "harness.h"
#include "vaultc/types.h"
#include "vaultc/importer.h"
#include "vaultc/crypto.h"
#include "vaultc/vault.h"
#include "vaultc/db.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Fixture paths (set via CMake compile definition) ──────────────────────── */

#define GOOGLE_CSV FIXTURES_DIR "/google_sample.csv"
#define FIREFOX_CSV FIXTURES_DIR "/firefox_sample.csv"
#define IOS_CSV FIXTURES_DIR "/ios_sample.csv"
#define BITWARDEN_CSV FIXTURES_DIR "/bitwarden_sample.csv"

/* ── Shared test vault ─────────────────────────────────────────────────────── */

#define TEST_VAULT "/tmp/vaultc_test_import.vcf"
#define TEST_PW "test-import-password"

static VaultHandle *create_test_vault(void)
{
    unlink(TEST_VAULT);
    return vault_create(TEST_VAULT, TEST_PW);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Format Detection Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(test_detect_google)
{
    ImportFormat fmt = import_detect_format(GOOGLE_CSV);
    ASSERT_EQ(fmt, IMPORT_GOOGLE);
}

TEST(test_detect_firefox)
{
    ImportFormat fmt = import_detect_format(FIREFOX_CSV);
    ASSERT_EQ(fmt, IMPORT_FIREFOX);
}

TEST(test_detect_ios)
{
    ImportFormat fmt = import_detect_format(IOS_CSV);
    ASSERT_EQ(fmt, IMPORT_IOS);
}

TEST(test_detect_bitwarden)
{
    ImportFormat fmt = import_detect_format(BITWARDEN_CSV);
    ASSERT_EQ(fmt, IMPORT_BITWARDEN);
}

TEST(test_detect_null)
{
    ImportFormat fmt = import_detect_format(NULL);
    ASSERT_EQ(fmt, IMPORT_UNKNOWN);
}

TEST(test_detect_nonexistent)
{
    ImportFormat fmt = import_detect_format("/tmp/nonexistent_csv_file.csv");
    ASSERT_EQ(fmt, IMPORT_UNKNOWN);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Google Import Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(test_google_import_count)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ImportResult r = import_google_csv(db, GOOGLE_CSV);

    ASSERT_EQ(r.imported, 3);
    ASSERT_EQ(r.skipped_duplicates, 0);
    ASSERT_EQ(r.errors, 0);
    ASSERT_EQ(r.format_detected, IMPORT_GOOGLE);

    vault_close(h);
    unlink(TEST_VAULT);
}

TEST(test_google_fields_mapped)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    import_google_csv(db, GOOGLE_CSV);

    /* Search for "Google Account" to find first entry */
    EntryList *list = db_entry_search(db, "Google Account");
    ASSERT_NOT_NULL(list);
    ASSERT_TRUE(list->count >= 1);

    Entry *e = list->items[0];
    ASSERT_STR_EQ(e->title, "Google Account");
    ASSERT_STR_EQ(e->url, "https://accounts.google.com");
    ASSERT_STR_EQ(e->username, "alice@gmail.com");
    ASSERT_STR_EQ(e->password, "G00gl3P@ss!");
    ASSERT_STR_EQ(e->source, "google");

    db_free_entry_list(list);
    vault_close(h);
    unlink(TEST_VAULT);
}

TEST(test_google_comma_in_title)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    import_google_csv(db, GOOGLE_CSV);

    /* The second entry has a quoted title with comma: "GitHub, Inc." */
    EntryList *list = db_entry_search(db, "GitHub");
    ASSERT_NOT_NULL(list);
    ASSERT_TRUE(list->count >= 1);

    Entry *e = list->items[0];
    ASSERT_STR_EQ(e->title, "GitHub, Inc.");

    db_free_entry_list(list);
    vault_close(h);
    unlink(TEST_VAULT);
}

TEST(test_google_duplicate_detection)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);

    /* First import: all 3 entries imported */
    ImportResult r1 = import_google_csv(db, GOOGLE_CSV);
    ASSERT_EQ(r1.imported, 3);
    ASSERT_EQ(r1.skipped_duplicates, 0);

    /* Second import: 0 imported, 3 skipped as duplicates */
    ImportResult r2 = import_google_csv(db, GOOGLE_CSV);
    ASSERT_EQ(r2.imported, 0);
    ASSERT_EQ(r2.skipped_duplicates, 3);

    vault_close(h);
    unlink(TEST_VAULT);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Firefox Import Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(test_firefox_import_count)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ImportResult r = import_firefox_csv(db, FIREFOX_CSV);

    ASSERT_EQ(r.imported, 3);
    ASSERT_EQ(r.skipped_duplicates, 0);
    ASSERT_EQ(r.errors, 0);
    ASSERT_EQ(r.format_detected, IMPORT_FIREFOX);

    vault_close(h);
    unlink(TEST_VAULT);
}

TEST(test_firefox_title_derivation)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    import_firefox_csv(db, FIREFOX_CSV);

    /* Title should be derived from hostname */
    EntryList *list = db_entry_search(db, "reddit");
    ASSERT_NOT_NULL(list);
    ASSERT_TRUE(list->count >= 1);

    /* "Firefox Import — www.reddit.com" */
    ASSERT_STR_EQ(list->items[0]->title,
                  "Firefox Import — www.reddit.com");
    ASSERT_STR_EQ(list->items[0]->source, "firefox");

    db_free_entry_list(list);
    vault_close(h);
    unlink(TEST_VAULT);
}

TEST(test_firefox_duplicate_detection)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);

    ImportResult r1 = import_firefox_csv(db, FIREFOX_CSV);
    ASSERT_EQ(r1.imported, 3);

    ImportResult r2 = import_firefox_csv(db, FIREFOX_CSV);
    ASSERT_EQ(r2.imported, 0);
    ASSERT_EQ(r2.skipped_duplicates, 3);

    vault_close(h);
    unlink(TEST_VAULT);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * iOS Import Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(test_ios_import_count)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ImportResult r = import_ios_csv(db, IOS_CSV);

    ASSERT_EQ(r.imported, 2);
    ASSERT_EQ(r.skipped_duplicates, 0);
    ASSERT_EQ(r.errors, 0);
    ASSERT_EQ(r.format_detected, IMPORT_IOS);

    vault_close(h);
    unlink(TEST_VAULT);
}

TEST(test_ios_totp_extraction)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    import_ios_csv(db, IOS_CSV);

    /* Dropbox entry should have extracted TOTP secret */
    EntryList *list = db_entry_search(db, "Dropbox");
    ASSERT_NOT_NULL(list);
    ASSERT_TRUE(list->count >= 1);

    Entry *e = list->items[0];
    ASSERT_STR_EQ(e->title, "Dropbox");
    ASSERT_STR_EQ(e->url, "https://www.dropbox.com");
    ASSERT_STR_EQ(e->password, "Dr0pB0x!");
    ASSERT_STR_EQ(e->source, "ios");

    /* totp_secret should be the extracted secret, NOT the raw URI */
    ASSERT_NOT_NULL(e->totp_secret);
    ASSERT_STR_EQ(e->totp_secret, "JBSWY3DPEHPK3PXP");

    db_free_entry_list(list);
    vault_close(h);
    unlink(TEST_VAULT);
}

TEST(test_ios_no_totp)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    import_ios_csv(db, IOS_CSV);

    /* Twitter entry should have no TOTP secret */
    EntryList *list = db_entry_search(db, "Twitter");
    ASSERT_NOT_NULL(list);
    ASSERT_TRUE(list->count >= 1);

    ASSERT_NULL(list->items[0]->totp_secret);

    db_free_entry_list(list);
    vault_close(h);
    unlink(TEST_VAULT);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Bitwarden Import Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(test_bitwarden_import_count)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ImportResult r = import_bitwarden_csv(db, BITWARDEN_CSV);

    /* 4 rows total, 1 is a card (skipped), 3 are logins */
    ASSERT_EQ(r.imported, 3);
    ASSERT_EQ(r.skipped_duplicates, 0);
    ASSERT_EQ(r.errors, 0);
    ASSERT_EQ(r.format_detected, IMPORT_BITWARDEN);

    vault_close(h);
    unlink(TEST_VAULT);
}

TEST(test_bitwarden_fields_mapped)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    import_bitwarden_csv(db, BITWARDEN_CSV);

    /* Check Facebook entry (has folder = "Social") */
    EntryList *list = db_entry_search(db, "Facebook");
    ASSERT_NOT_NULL(list);
    ASSERT_TRUE(list->count >= 1);

    Entry *e = list->items[0];
    ASSERT_STR_EQ(e->title, "Facebook");
    ASSERT_STR_EQ(e->url, "https://facebook.com");
    ASSERT_STR_EQ(e->username, "dave@email.com");
    ASSERT_STR_EQ(e->password, "F@c3b00k!");
    ASSERT_STR_EQ(e->category, "Social");
    ASSERT_STR_EQ(e->source, "bitwarden");

    db_free_entry_list(list);
    vault_close(h);
    unlink(TEST_VAULT);
}

TEST(test_bitwarden_totp_preserved)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    import_bitwarden_csv(db, BITWARDEN_CSV);

    /* Slack entry should have TOTP secret */
    EntryList *list = db_entry_search(db, "Slack");
    ASSERT_NOT_NULL(list);
    ASSERT_TRUE(list->count >= 1);

    ASSERT_NOT_NULL(list->items[0]->totp_secret);
    ASSERT_STR_EQ(list->items[0]->totp_secret, "JBSWY3DPEHPK3PXP");

    db_free_entry_list(list);
    vault_close(h);
    unlink(TEST_VAULT);
}

TEST(test_bitwarden_card_skipped)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    import_bitwarden_csv(db, BITWARDEN_CSV);

    /* "Visa Card" row (type=card) should NOT appear in the database */
    EntryList *list = db_entry_search(db, "Visa Card");
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, 0);

    db_free_entry_list(list);
    vault_close(h);
    unlink(TEST_VAULT);
}

TEST(test_bitwarden_duplicate_detection)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);

    ImportResult r1 = import_bitwarden_csv(db, BITWARDEN_CSV);
    ASSERT_EQ(r1.imported, 3);

    ImportResult r2 = import_bitwarden_csv(db, BITWARDEN_CSV);
    ASSERT_EQ(r2.imported, 0);
    ASSERT_EQ(r2.skipped_duplicates, 3);

    vault_close(h);
    unlink(TEST_VAULT);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void)
{
    crypto_init();

    /* Format detection */
    RUN_TEST(test_detect_google);
    RUN_TEST(test_detect_firefox);
    RUN_TEST(test_detect_ios);
    RUN_TEST(test_detect_bitwarden);
    RUN_TEST(test_detect_null);
    RUN_TEST(test_detect_nonexistent);

    /* Google importer */
    RUN_TEST(test_google_import_count);
    RUN_TEST(test_google_fields_mapped);
    RUN_TEST(test_google_comma_in_title);
    RUN_TEST(test_google_duplicate_detection);

    /* Firefox importer */
    RUN_TEST(test_firefox_import_count);
    RUN_TEST(test_firefox_title_derivation);
    RUN_TEST(test_firefox_duplicate_detection);

    /* iOS importer */
    RUN_TEST(test_ios_import_count);
    RUN_TEST(test_ios_totp_extraction);
    RUN_TEST(test_ios_no_totp);

    /* Bitwarden importer */
    RUN_TEST(test_bitwarden_import_count);
    RUN_TEST(test_bitwarden_fields_mapped);
    RUN_TEST(test_bitwarden_totp_preserved);
    RUN_TEST(test_bitwarden_card_skipped);
    RUN_TEST(test_bitwarden_duplicate_detection);

    PRINT_RESULTS();
    return g_tests_failed > 0 ? 1 : 0;
}
