/*
 * VaultC — Vault I/O Tests
 * File: tests/test_vault.c
 */

#include "harness.h"
#include "vaultc/vault.h"
#include "vaultc/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

/* Test vault file path — created/deleted per test */
static const char *TEST_VAULT = "/tmp/vaultc_test.vcf";
static const char *TEST_PASS = "test-master-password-42";
static const char *WRONG_PASS = "wrong-password-99";

/* ── Helper: remove test vault file ────────────────────────────────────────── */

static void cleanup_test_vault(void)
{
    remove(TEST_VAULT);
    /* Also remove any leftover temp file */
    remove("/tmp/vaultc_test.vcf.tmp");
}

/* ── Test: vault_create produces a file with correct magic bytes ───────────── */

TEST(test_vault_create_magic_bytes)
{
    cleanup_test_vault();

    ASSERT_EQ(crypto_init(), VAULTC_OK);

    VaultHandle *h = vault_create(TEST_VAULT, TEST_PASS);
    ASSERT_NOT_NULL(h);
    vault_close(h);

    /* Read the file and check magic bytes */
    FILE *f = fopen(TEST_VAULT, "rb");
    ASSERT_NOT_NULL(f);

    uint8_t magic[4];
    size_t n = fread(magic, 1, 4, f);
    fclose(f);

    ASSERT_EQ(n, (size_t)4);
    ASSERT_EQ(magic[0], VAULTC_MAGIC_0);
    ASSERT_EQ(magic[1], VAULTC_MAGIC_1);
    ASSERT_EQ(magic[2], VAULTC_MAGIC_2);
    ASSERT_EQ(magic[3], VAULTC_MAGIC_3);

    cleanup_test_vault();
}

/* ── Test: vault_create produces file with correct version ─────────────────── */

TEST(test_vault_create_version)
{
    cleanup_test_vault();

    VaultHandle *h = vault_create(TEST_VAULT, TEST_PASS);
    ASSERT_NOT_NULL(h);
    vault_close(h);

    FILE *f = fopen(TEST_VAULT, "rb");
    ASSERT_NOT_NULL(f);

    VaultFileHeader header;
    size_t n = fread(&header, 1, sizeof(header), f);
    fclose(f);

    ASSERT_EQ(n, sizeof(header));
    ASSERT_EQ(header.version, VAULTC_VERSION);

    cleanup_test_vault();
}

/* ── Test: vault_open with correct password succeeds ───────────────────────── */

TEST(test_vault_open_correct_password)
{
    cleanup_test_vault();

    VaultHandle *h = vault_create(TEST_VAULT, TEST_PASS);
    ASSERT_NOT_NULL(h);
    vault_close(h);

    h = vault_open(TEST_VAULT, TEST_PASS);
    ASSERT_NOT_NULL(h);
    vault_close(h);

    cleanup_test_vault();
}

/* ── Test: vault_open with wrong password returns NULL ──────────────────────── */

TEST(test_vault_open_wrong_password)
{
    cleanup_test_vault();

    VaultHandle *h = vault_create(TEST_VAULT, TEST_PASS);
    ASSERT_NOT_NULL(h);
    vault_close(h);

    h = vault_open(TEST_VAULT, WRONG_PASS);
    ASSERT_NULL(h);

    cleanup_test_vault();
}

/* ── Test: vault_open on truncated file returns NULL ────────────────────────── */

TEST(test_vault_open_truncated_file)
{
    cleanup_test_vault();

    /* Write a truncated file (less than 92 bytes header) */
    FILE *f = fopen(TEST_VAULT, "wb");
    ASSERT_NOT_NULL(f);

    uint8_t garbage[40];
    memset(garbage, 0xAB, sizeof(garbage));
    fwrite(garbage, 1, sizeof(garbage), f);
    fclose(f);

    VaultHandle *h = vault_open(TEST_VAULT, TEST_PASS);
    ASSERT_NULL(h);

    cleanup_test_vault();
}

/* ── Test: vault_open on file with bad magic returns NULL ───────────────────── */

TEST(test_vault_open_bad_magic)
{
    cleanup_test_vault();

    /* Write a file with valid size but wrong magic */
    FILE *f = fopen(TEST_VAULT, "wb");
    ASSERT_NOT_NULL(f);

    VaultFileHeader bad_header;
    memset(&bad_header, 0, sizeof(bad_header));
    bad_header.magic[0] = 0xDE;
    bad_header.magic[1] = 0xAD;
    bad_header.magic[2] = 0xBE;
    bad_header.magic[3] = 0xEF;
    bad_header.version = VAULTC_VERSION;
    bad_header.ciphertext_len = 64;

    fwrite(&bad_header, 1, sizeof(bad_header), f);

    /* Write some dummy ciphertext */
    uint8_t dummy[64];
    memset(dummy, 0, sizeof(dummy));
    fwrite(dummy, 1, sizeof(dummy), f);
    fclose(f);

    VaultHandle *h = vault_open(TEST_VAULT, TEST_PASS);
    ASSERT_NULL(h);

    cleanup_test_vault();
}

/* ── Test: vault_save + vault_open round-trip — metadata survives ──────────── */

TEST(test_vault_roundtrip_metadata)
{
    cleanup_test_vault();

    VaultHandle *h = vault_create(TEST_VAULT, TEST_PASS);
    ASSERT_NOT_NULL(h);
    vault_close(h);

    /* Re-open and check metadata */
    h = vault_open(TEST_VAULT, TEST_PASS);
    ASSERT_NOT_NULL(h);

    sqlite3 *db = (sqlite3 *)vault_get_db(h);
    ASSERT_NOT_NULL(db);

    /* Query schema_version from metadata */
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
                                "SELECT value FROM metadata WHERE key = 'schema_version'",
                                -1, &stmt, NULL);
    ASSERT_EQ(rc, SQLITE_OK);

    rc = sqlite3_step(stmt);
    ASSERT_EQ(rc, SQLITE_ROW);

    const char *version_str = (const char *)sqlite3_column_text(stmt, 0);
    ASSERT_NOT_NULL(version_str);
    ASSERT_STR_EQ(version_str, "1");

    sqlite3_finalize(stmt);

    /* Query vault_name */
    rc = sqlite3_prepare_v2(db,
                            "SELECT value FROM metadata WHERE key = 'vault_name'",
                            -1, &stmt, NULL);
    ASSERT_EQ(rc, SQLITE_OK);

    rc = sqlite3_step(stmt);
    ASSERT_EQ(rc, SQLITE_ROW);

    const char *vault_name = (const char *)sqlite3_column_text(stmt, 0);
    ASSERT_NOT_NULL(vault_name);
    ASSERT_STR_EQ(vault_name, "My Vault");

    sqlite3_finalize(stmt);
    vault_close(h);

    cleanup_test_vault();
}

/* ── Test: vault_create with NULL args returns NULL ─────────────────────────── */

TEST(test_vault_create_null_args)
{
    ASSERT_NULL(vault_create(NULL, TEST_PASS));
    ASSERT_NULL(vault_create(TEST_VAULT, NULL));
    ASSERT_NULL(vault_create(NULL, NULL));
}

/* ── Test: vault_open with NULL args returns NULL ──────────────────────────── */

TEST(test_vault_open_null_args)
{
    ASSERT_NULL(vault_open(NULL, TEST_PASS));
    ASSERT_NULL(vault_open(TEST_VAULT, NULL));
    ASSERT_NULL(vault_open(NULL, NULL));
}

/* ── Test: vault_save with NULL returns error ──────────────────────────────── */

TEST(test_vault_save_null)
{
    ASSERT_EQ(vault_save(NULL), VAULTC_ERR_INVALID_ARG);
}

/* ── Test: vault file size is header + ciphertext ──────────────────────────── */

TEST(test_vault_file_size)
{
    cleanup_test_vault();

    VaultHandle *h = vault_create(TEST_VAULT, TEST_PASS);
    ASSERT_NOT_NULL(h);
    vault_close(h);

    FILE *f = fopen(TEST_VAULT, "rb");
    ASSERT_NOT_NULL(f);

    VaultFileHeader header;
    size_t n = fread(&header, 1, sizeof(header), f);
    ASSERT_EQ(n, sizeof(header));

    /* Seek to end to get total file size */
    fseek(f, 0, SEEK_END);
    long total = ftell(f);
    fclose(f);

    ASSERT_EQ((uint64_t)(total - (long)sizeof(VaultFileHeader)),
              header.ciphertext_len);

    cleanup_test_vault();
}

/* ── Test: vault_save generates different nonces each time ─────────────────── */

TEST(test_vault_save_fresh_nonce)
{
    cleanup_test_vault();

    VaultHandle *h = vault_create(TEST_VAULT, TEST_PASS);
    ASSERT_NOT_NULL(h);

    /* Read nonce from the saved file */
    FILE *f = fopen(TEST_VAULT, "rb");
    ASSERT_NOT_NULL(f);
    VaultFileHeader hdr1;
    fread(&hdr1, 1, sizeof(hdr1), f);
    fclose(f);

    /* Save again — should generate a fresh nonce */
    ASSERT_EQ(vault_save(h), VAULTC_OK);

    f = fopen(TEST_VAULT, "rb");
    ASSERT_NOT_NULL(f);
    VaultFileHeader hdr2;
    fread(&hdr2, 1, sizeof(hdr2), f);
    fclose(f);

    /* Nonces must differ between saves */
    ASSERT_TRUE(memcmp(hdr1.nonce, hdr2.nonce, VAULTC_HEADER_NONCE_BYTES) != 0);

    vault_close(h);
    cleanup_test_vault();
}

/* ── Test: vault_change_password works ─────────────────────────────────────── */

TEST(test_vault_change_password)
{
    cleanup_test_vault();

    VaultHandle *h = vault_create(TEST_VAULT, TEST_PASS);
    ASSERT_NOT_NULL(h);

    const char *new_pass = "new-super-secret-password";

    ASSERT_EQ(vault_change_password(h, TEST_PASS, new_pass), VAULTC_OK);
    vault_close(h);

    /* Old password should fail */
    h = vault_open(TEST_VAULT, TEST_PASS);
    ASSERT_NULL(h);

    /* New password should work */
    h = vault_open(TEST_VAULT, new_pass);
    ASSERT_NOT_NULL(h);
    vault_close(h);

    cleanup_test_vault();
}

/* ── Test: vault_change_password with wrong old password fails ─────────────── */

TEST(test_vault_change_password_wrong_old)
{
    cleanup_test_vault();

    VaultHandle *h = vault_create(TEST_VAULT, TEST_PASS);
    ASSERT_NOT_NULL(h);

    ASSERT_EQ(vault_change_password(h, WRONG_PASS, "new-pass"),
              VAULTC_ERR_BAD_PASSWORD);

    vault_close(h);
    cleanup_test_vault();
}

/* ── main ───────────────────────────────────────────────────────────────────── */

int main(void)
{
    /* Must init crypto before any vault operations */
    crypto_init();

    RUN_TEST(test_vault_create_magic_bytes);
    RUN_TEST(test_vault_create_version);
    RUN_TEST(test_vault_open_correct_password);
    RUN_TEST(test_vault_open_wrong_password);
    RUN_TEST(test_vault_open_truncated_file);
    RUN_TEST(test_vault_open_bad_magic);
    RUN_TEST(test_vault_roundtrip_metadata);
    RUN_TEST(test_vault_create_null_args);
    RUN_TEST(test_vault_open_null_args);
    RUN_TEST(test_vault_save_null);
    RUN_TEST(test_vault_file_size);
    RUN_TEST(test_vault_save_fresh_nonce);
    RUN_TEST(test_vault_change_password);
    RUN_TEST(test_vault_change_password_wrong_old);
    PRINT_RESULTS();
    return g_tests_failed > 0 ? 1 : 0;
}
