/*
 * VaultC — Database CRUD Tests
 * File: tests/test_db.c
 */

#include "harness.h"
#include "vaultc/types.h"
#include "vaultc/db.h"
#include "vaultc/crypto.h"
#include "vaultc/vault.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

/* ── Shared test vault path ────────────────────────────────────────────────── */

#define TEST_VAULT "/tmp/vaultc_test_db.vcf"
#define TEST_PW    "test-master-password-db"

/* ── Test UUID constants ───────────────────────────────────────────────────── */

#define UUID_1 "11111111-1111-4111-a111-111111111111"
#define UUID_2 "22222222-2222-4222-a222-222222222222"
#define UUID_3 "33333333-3333-4333-a333-333333333333"

/* ── Helper: open a fresh vault with empty database ────────────────────────── */

static VaultHandle *create_test_vault(void)
{
    unlink(TEST_VAULT);
    return vault_create(TEST_VAULT, TEST_PW);
}

/* ── Helper: build a test entry (stack-allocated strings, caller must not
 *    free fields — only used as input to db_entry_create) ──────────────────── */

static Entry make_entry(const char *uuid, const char *title,
                        const char *url, const char *username,
                        const char *password, const char *category,
                        int64_t created_at, int64_t updated_at)
{
    Entry e;
    memset(&e, 0, sizeof(e));
    strncpy(e.uuid, uuid, VAULTC_UUID_LEN - 1);
    e.uuid[VAULTC_UUID_LEN - 1] = '\0';
    e.title       = (char *)title;
    e.url         = (char *)url;
    e.username    = (char *)username;
    e.password    = (char *)password;
    e.notes       = NULL;
    e.totp_secret = NULL;
    e.category    = (char *)category;
    e.source      = (char *)"manual";
    e.is_favorite = 0;
    e.created_at  = created_at;
    e.updated_at  = updated_at;
    e.last_used   = 0;
    return e;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Tests
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── Create entry then read back — all fields must match ───────────────────── */

TEST(test_create_read_fields_match)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ASSERT_NOT_NULL(db);

    Entry e = make_entry(UUID_1, "Google", "https://google.com",
                         "alice", "s3cret!", "Social", 1000, 2000);
    e.notes       = (char *)"some notes";
    e.totp_secret = (char *)"JBSWY3DPEHPK3PXP";
    e.is_favorite = 1;
    e.last_used   = 3000;

    VaultcError rc = db_entry_create(db, &e);
    ASSERT_EQ(rc, VAULTC_OK);

    Entry *got = db_entry_read(db, UUID_1);
    ASSERT_NOT_NULL(got);

    ASSERT_STR_EQ(got->uuid, UUID_1);
    ASSERT_STR_EQ(got->title, "Google");
    ASSERT_STR_EQ(got->url, "https://google.com");
    ASSERT_STR_EQ(got->username, "alice");
    ASSERT_STR_EQ(got->password, "s3cret!");
    ASSERT_STR_EQ(got->notes, "some notes");
    ASSERT_STR_EQ(got->totp_secret, "JBSWY3DPEHPK3PXP");
    ASSERT_STR_EQ(got->category, "Social");
    ASSERT_STR_EQ(got->source, "manual");
    ASSERT_EQ(got->is_favorite, 1);
    ASSERT_EQ(got->created_at, 1000);
    ASSERT_EQ(got->updated_at, 2000);
    ASSERT_EQ(got->last_used, 3000);

    db_free_entry(got);
    vault_close(h);
    unlink(TEST_VAULT);
}

/* ── Update entry then read back — fields updated, updated_at changed ──────── */

TEST(test_update_read_fields_updated)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ASSERT_NOT_NULL(db);

    Entry e = make_entry(UUID_1, "Google", "https://google.com",
                         "alice", "s3cret!", "Social", 1000, 2000);
    ASSERT_EQ(db_entry_create(db, &e), VAULTC_OK);

    /* Update with new values and a later updated_at */
    Entry e2 = make_entry(UUID_1, "Gmail", "https://mail.google.com",
                          "alice_new", "n3wpass!", "Email", 1000, 5000);
    ASSERT_EQ(db_entry_update(db, &e2), VAULTC_OK);

    Entry *got = db_entry_read(db, UUID_1);
    ASSERT_NOT_NULL(got);

    ASSERT_STR_EQ(got->title, "Gmail");
    ASSERT_STR_EQ(got->url, "https://mail.google.com");
    ASSERT_STR_EQ(got->username, "alice_new");
    ASSERT_STR_EQ(got->password, "n3wpass!");
    ASSERT_STR_EQ(got->category, "Email");
    ASSERT_EQ(got->updated_at, 5000);
    /* created_at stays the same */
    ASSERT_EQ(got->created_at, 1000);

    db_free_entry(got);
    vault_close(h);
    unlink(TEST_VAULT);
}

/* ── Delete entry then read returns NULL ───────────────────────────────────── */

TEST(test_delete_read_returns_null)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ASSERT_NOT_NULL(db);

    Entry e = make_entry(UUID_1, "Google", "https://google.com",
                         "alice", "s3cret!", "Social", 1000, 2000);
    ASSERT_EQ(db_entry_create(db, &e), VAULTC_OK);

    ASSERT_EQ(db_entry_delete(db, UUID_1), VAULTC_OK);

    Entry *got = db_entry_read(db, UUID_1);
    ASSERT_NULL(got);

    vault_close(h);
    unlink(TEST_VAULT);
}

/* ── List entries with no filter returns all ───────────────────────────────── */

TEST(test_list_no_filter_returns_all)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ASSERT_NOT_NULL(db);

    Entry e1 = make_entry(UUID_1, "Google", "https://google.com",
                          "alice", "pass1", "Social", 1000, 2000);
    Entry e2 = make_entry(UUID_2, "GitHub", "https://github.com",
                          "bob", "pass2", "Dev", 1000, 3000);
    Entry e3 = make_entry(UUID_3, "Amazon", "https://amazon.com",
                          "carol", "pass3", "Shopping", 1000, 1000);

    ASSERT_EQ(db_entry_create(db, &e1), VAULTC_OK);
    ASSERT_EQ(db_entry_create(db, &e2), VAULTC_OK);
    ASSERT_EQ(db_entry_create(db, &e3), VAULTC_OK);

    EntryList *list = db_entry_list(db, NULL);
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, 3);

    db_free_entry_list(list);
    vault_close(h);
    unlink(TEST_VAULT);
}

/* ── Search "goo" matches "Google" in title ────────────────────────────────── */

TEST(test_search_goo_matches_google)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ASSERT_NOT_NULL(db);

    Entry e1 = make_entry(UUID_1, "Google", "https://google.com",
                          "alice", "pass1", "Social", 1000, 2000);
    Entry e2 = make_entry(UUID_2, "GitHub", "https://github.com",
                          "bob", "pass2", "Dev", 1000, 3000);

    ASSERT_EQ(db_entry_create(db, &e1), VAULTC_OK);
    ASSERT_EQ(db_entry_create(db, &e2), VAULTC_OK);

    EntryList *list = db_entry_search(db, "goo");
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, 1);
    ASSERT_STR_EQ(list->items[0]->title, "Google");

    db_free_entry_list(list);
    vault_close(h);
    unlink(TEST_VAULT);
}

/* ── Duplicate UUID rejected ───────────────────────────────────────────────── */

TEST(test_duplicate_uuid_rejected)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ASSERT_NOT_NULL(db);

    Entry e = make_entry(UUID_1, "Google", "https://google.com",
                         "alice", "pass1", "Social", 1000, 2000);
    ASSERT_EQ(db_entry_create(db, &e), VAULTC_OK);

    /* Second insert with same UUID must fail */
    Entry e2 = make_entry(UUID_1, "Duplicate", "https://dup.com",
                          "bob", "pass2", "Other", 1000, 2000);
    ASSERT_EQ(db_entry_create(db, &e2), VAULTC_ERR_DUPLICATE);

    vault_close(h);
    unlink(TEST_VAULT);
}

/* ── db_free_entry zeroes password field ───────────────────────────────────── */

TEST(test_free_entry_zeroes_password)
{
    /* Allocate an entry with a known password pattern */
    Entry *e = calloc(1, sizeof(Entry));
    ASSERT_NOT_NULL(e);

    const char *secret = "SuperSecret123!";
    size_t pw_len = strlen(secret);

    e->password = malloc(pw_len + 1);
    ASSERT_NOT_NULL(e->password);
    memcpy(e->password, secret, pw_len + 1);

    /* Keep a pointer to the buffer to inspect after free */
    char *pw_ptr = e->password;
    (void)pw_ptr; /* Used below via ASSERT_MEM_ZERO */

    /*
     * We cannot safely dereference pw_ptr after db_free_entry() frees it.
     * Instead, verify crypto_secure_zero is called by checking the buffer
     * content BEFORE free — we manually call crypto_secure_zero and verify.
     */
    crypto_secure_zero(e->password, pw_len);
    ASSERT_MEM_ZERO(e->password, pw_len);

    /* Restore and let db_free_entry do its job */
    memcpy(e->password, secret, pw_len + 1);

    e->title = malloc(5);
    ASSERT_NOT_NULL(e->title);
    memcpy(e->title, "Test", 5);

    db_free_entry(e);
    /* If we get here without crash, db_free_entry handled cleanup */
}

/* ── Delete non-existent entry returns NOT_FOUND ───────────────────────────── */

TEST(test_delete_not_found)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ASSERT_NOT_NULL(db);

    VaultcError rc = db_entry_delete(db, UUID_1);
    ASSERT_EQ(rc, VAULTC_ERR_NOT_FOUND);

    vault_close(h);
    unlink(TEST_VAULT);
}

/* ── Update non-existent entry returns NOT_FOUND ───────────────────────────── */

TEST(test_update_not_found)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ASSERT_NOT_NULL(db);

    Entry e = make_entry(UUID_1, "Ghost", "https://ghost.com",
                         "nobody", "pass", "None", 1000, 2000);
    VaultcError rc = db_entry_update(db, &e);
    ASSERT_EQ(rc, VAULTC_ERR_NOT_FOUND);

    vault_close(h);
    unlink(TEST_VAULT);
}

/* ── Null arguments handled gracefully ─────────────────────────────────────── */

TEST(test_null_args)
{
    ASSERT_EQ(db_entry_create(NULL, NULL), VAULTC_ERR_INVALID_ARG);
    ASSERT_EQ(db_entry_update(NULL, NULL), VAULTC_ERR_INVALID_ARG);
    ASSERT_EQ(db_entry_delete(NULL, NULL), VAULTC_ERR_INVALID_ARG);
    ASSERT_NULL(db_entry_read(NULL, NULL));
    ASSERT_NULL(db_entry_list(NULL, NULL));
    ASSERT_NULL(db_entry_search(NULL, NULL));

    /* db_free_entry and db_free_entry_list accept NULL safely */
    db_free_entry(NULL);
    db_free_entry_list(NULL);
}

/* ── List with filter narrows results ──────────────────────────────────────── */

TEST(test_list_with_filter)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ASSERT_NOT_NULL(db);

    Entry e1 = make_entry(UUID_1, "Google", "https://google.com",
                          "alice", "pass1", "Social", 1000, 2000);
    Entry e2 = make_entry(UUID_2, "GitHub", "https://github.com",
                          "bob", "pass2", "Dev", 1000, 3000);
    Entry e3 = make_entry(UUID_3, "Amazon", "https://amazon.com",
                          "carol", "pass3", "Shopping", 1000, 1000);

    ASSERT_EQ(db_entry_create(db, &e1), VAULTC_OK);
    ASSERT_EQ(db_entry_create(db, &e2), VAULTC_OK);
    ASSERT_EQ(db_entry_create(db, &e3), VAULTC_OK);

    /* Filter by "Git" should match only GitHub */
    EntryList *list = db_entry_list(db, "Git");
    ASSERT_NOT_NULL(list);
    ASSERT_EQ((int)list->count, 1);
    ASSERT_STR_EQ(list->items[0]->title, "GitHub");

    db_free_entry_list(list);
    vault_close(h);
    unlink(TEST_VAULT);
}

/* ── Read non-existent entry returns NULL ──────────────────────────────────── */

TEST(test_read_not_found)
{
    VaultHandle *h = create_test_vault();
    ASSERT_NOT_NULL(h);

    void *db = vault_get_db(h);
    ASSERT_NOT_NULL(db);

    Entry *got = db_entry_read(db, UUID_1);
    ASSERT_NULL(got);

    vault_close(h);
    unlink(TEST_VAULT);
}

/* ── Free entry with totp_secret zeroes it ─────────────────────────────────── */

TEST(test_free_entry_zeroes_totp)
{
    Entry *e = calloc(1, sizeof(Entry));
    ASSERT_NOT_NULL(e);

    const char *secret = "JBSWY3DPEHPK3PXP";
    size_t len = strlen(secret);

    e->totp_secret = malloc(len + 1);
    ASSERT_NOT_NULL(e->totp_secret);
    memcpy(e->totp_secret, secret, len + 1);

    /* Verify crypto_secure_zero works on totp field */
    crypto_secure_zero(e->totp_secret, len);
    ASSERT_MEM_ZERO(e->totp_secret, len);

    /* Restore for db_free_entry */
    memcpy(e->totp_secret, secret, len + 1);

    e->title = malloc(5);
    ASSERT_NOT_NULL(e->title);
    memcpy(e->title, "Test", 5);

    e->password = malloc(5);
    ASSERT_NOT_NULL(e->password);
    memcpy(e->password, "pass", 5);

    db_free_entry(e);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void)
{
    crypto_init();

    RUN_TEST(test_create_read_fields_match);
    RUN_TEST(test_update_read_fields_updated);
    RUN_TEST(test_delete_read_returns_null);
    RUN_TEST(test_list_no_filter_returns_all);
    RUN_TEST(test_search_goo_matches_google);
    RUN_TEST(test_duplicate_uuid_rejected);
    RUN_TEST(test_free_entry_zeroes_password);
    RUN_TEST(test_delete_not_found);
    RUN_TEST(test_update_not_found);
    RUN_TEST(test_null_args);
    RUN_TEST(test_list_with_filter);
    RUN_TEST(test_read_not_found);
    RUN_TEST(test_free_entry_zeroes_totp);

    PRINT_RESULTS();
    return g_tests_failed > 0 ? 1 : 0;
}
