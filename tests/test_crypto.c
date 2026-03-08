/*
 * VaultC — Crypto Layer Tests
 * File: tests/test_crypto.c
 */

#include "harness.h"
#include "vaultc/crypto.h"

#include <stdlib.h>

/* ── Test: crypto_init succeeds ─────────────────────────────────────────────── */

TEST(test_crypto_init_succeeds)
{
    VaultcError err = crypto_init();
    ASSERT_EQ(err, VAULTC_OK);
}

/* ── Test: crypto_init is idempotent (calling twice is safe) ────────────────── */

TEST(test_crypto_init_idempotent)
{
    ASSERT_EQ(crypto_init(), VAULTC_OK);
    ASSERT_EQ(crypto_init(), VAULTC_OK);
}

/* ── Test: crypto_derive_key is deterministic ───────────────────────────────── */

TEST(test_derive_key_deterministic)
{
    const char *password = "correct-horse-battery-staple";
    uint8_t salt[VAULTC_SALT_BYTES];
    memset(salt, 0x42, sizeof(salt));

    /* Use minimal cost for fast tests */
    uint32_t ops = 1;
    uint32_t mem = 8192;

    uint8_t key1[VAULTC_KEY_BYTES];
    uint8_t key2[VAULTC_KEY_BYTES];

    ASSERT_EQ(crypto_derive_key(password, salt, ops, mem, key1), VAULTC_OK);
    ASSERT_EQ(crypto_derive_key(password, salt, ops, mem, key2), VAULTC_OK);

    ASSERT_MEM_EQ(key1, key2, VAULTC_KEY_BYTES);

    crypto_secure_zero(key1, sizeof(key1));
    crypto_secure_zero(key2, sizeof(key2));
}

/* ── Test: crypto_derive_key avalanche — 1-char change → different key ──────── */

TEST(test_derive_key_avalanche)
{
    uint8_t salt[VAULTC_SALT_BYTES];
    memset(salt, 0xAA, sizeof(salt));

    uint32_t ops = 1;
    uint32_t mem = 8192;

    uint8_t key_a[VAULTC_KEY_BYTES];
    uint8_t key_b[VAULTC_KEY_BYTES];

    ASSERT_EQ(crypto_derive_key("passwordA", salt, ops, mem, key_a), VAULTC_OK);
    ASSERT_EQ(crypto_derive_key("passwordB", salt, ops, mem, key_b), VAULTC_OK);

    /* Keys must differ — memcmp returns non-zero */
    ASSERT_TRUE(memcmp(key_a, key_b, VAULTC_KEY_BYTES) != 0);

    crypto_secure_zero(key_a, sizeof(key_a));
    crypto_secure_zero(key_b, sizeof(key_b));
}

/* ── Test: crypto_derive_key rejects NULL arguments ─────────────────────────── */

TEST(test_derive_key_null_args)
{
    uint8_t salt[VAULTC_SALT_BYTES] = {0};
    uint8_t key[VAULTC_KEY_BYTES] = {0};

    ASSERT_EQ(crypto_derive_key(NULL, salt, 1, 8192, key),
              VAULTC_ERR_INVALID_ARG);
    ASSERT_EQ(crypto_derive_key("pw", NULL, 1, 8192, key),
              VAULTC_ERR_INVALID_ARG);
    ASSERT_EQ(crypto_derive_key("pw", salt, 1, 8192, NULL),
              VAULTC_ERR_INVALID_ARG);
}

/* ── Test: encrypt→decrypt round-trip ───────────────────────────────────────── */

TEST(test_encrypt_decrypt_roundtrip)
{
    const char *message = "Hello, VaultC! This is secret data.";
    size_t msg_len = strlen(message);

    uint8_t key[VAULTC_KEY_BYTES];
    uint8_t nonce[VAULTC_NONCE_BYTES];
    crypto_random_bytes(key, sizeof(key));
    crypto_random_bytes(nonce, sizeof(nonce));

    uint8_t *ciphertext = malloc(msg_len);
    ASSERT_NOT_NULL(ciphertext);

    uint8_t tag[VAULTC_TAG_BYTES];

    ASSERT_EQ(crypto_encrypt((const uint8_t *)message, msg_len,
                             key, nonce, ciphertext, tag),
              VAULTC_OK);

    /* Ciphertext must differ from plaintext */
    ASSERT_TRUE(memcmp(ciphertext, message, msg_len) != 0);

    uint8_t *decrypted = malloc(msg_len);
    ASSERT_NOT_NULL(decrypted);

    ASSERT_EQ(crypto_decrypt(ciphertext, msg_len,
                             key, nonce, tag, decrypted),
              VAULTC_OK);

    /* Decrypted text must match original */
    ASSERT_MEM_EQ(decrypted, message, msg_len);

    crypto_secure_zero(key, sizeof(key));
    free(ciphertext);
    ciphertext = NULL;
    free(decrypted);
    decrypted = NULL;
}

/* ── Test: decrypt with wrong key fails ─────────────────────────────────────── */

TEST(test_decrypt_wrong_key_fails)
{
    const char *message = "Secret payload";
    size_t msg_len = strlen(message);

    uint8_t key[VAULTC_KEY_BYTES];
    uint8_t wrong_key[VAULTC_KEY_BYTES];
    uint8_t nonce[VAULTC_NONCE_BYTES];
    crypto_random_bytes(key, sizeof(key));
    crypto_random_bytes(wrong_key, sizeof(wrong_key));
    crypto_random_bytes(nonce, sizeof(nonce));

    uint8_t *ciphertext = malloc(msg_len);
    ASSERT_NOT_NULL(ciphertext);
    uint8_t tag[VAULTC_TAG_BYTES];

    ASSERT_EQ(crypto_encrypt((const uint8_t *)message, msg_len,
                             key, nonce, ciphertext, tag),
              VAULTC_OK);

    uint8_t *decrypted = malloc(msg_len);
    ASSERT_NOT_NULL(decrypted);

    /* Decrypt with wrong key must fail */
    ASSERT_EQ(crypto_decrypt(ciphertext, msg_len,
                             wrong_key, nonce, tag, decrypted),
              VAULTC_ERR_BAD_PASSWORD);

    crypto_secure_zero(key, sizeof(key));
    crypto_secure_zero(wrong_key, sizeof(wrong_key));
    free(ciphertext);
    ciphertext = NULL;
    free(decrypted);
    decrypted = NULL;
}

/* ── Test: decrypt with tampered ciphertext fails ───────────────────────────── */

TEST(test_decrypt_tampered_ciphertext_fails)
{
    const char *message = "Tamper test payload";
    size_t msg_len = strlen(message);

    uint8_t key[VAULTC_KEY_BYTES];
    uint8_t nonce[VAULTC_NONCE_BYTES];
    crypto_random_bytes(key, sizeof(key));
    crypto_random_bytes(nonce, sizeof(nonce));

    uint8_t *ciphertext = malloc(msg_len);
    ASSERT_NOT_NULL(ciphertext);
    uint8_t tag[VAULTC_TAG_BYTES];

    ASSERT_EQ(crypto_encrypt((const uint8_t *)message, msg_len,
                             key, nonce, ciphertext, tag),
              VAULTC_OK);

    /* Flip one bit in the ciphertext */
    ciphertext[0] ^= 0x01;

    uint8_t *decrypted = malloc(msg_len);
    ASSERT_NOT_NULL(decrypted);

    ASSERT_EQ(crypto_decrypt(ciphertext, msg_len,
                             key, nonce, tag, decrypted),
              VAULTC_ERR_BAD_PASSWORD);

    crypto_secure_zero(key, sizeof(key));
    free(ciphertext);
    ciphertext = NULL;
    free(decrypted);
    decrypted = NULL;
}

/* ── Test: crypto_random_bytes produces non-zero output ─────────────────────── */

TEST(test_random_bytes_not_all_zero)
{
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));

    ASSERT_EQ(crypto_random_bytes(buf, sizeof(buf)), VAULTC_OK);

    /* Extremely unlikely that 64 random bytes are all zero */
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(buf); i++)
    {
        if (buf[i] != 0)
        {
            all_zero = 0;
            break;
        }
    }
    ASSERT_FALSE(all_zero);
}

/* ── Test: crypto_random_bytes rejects NULL ──────────────────────────────────── */

TEST(test_random_bytes_null_arg)
{
    ASSERT_EQ(crypto_random_bytes(NULL, 32), VAULTC_ERR_INVALID_ARG);
}

/* ── Test: crypto_encrypt rejects NULL arguments ────────────────────────────── */

TEST(test_encrypt_null_args)
{
    uint8_t key[VAULTC_KEY_BYTES] = {0};
    uint8_t nonce[VAULTC_NONCE_BYTES] = {0};
    uint8_t buf[16] = {0};
    uint8_t tag[VAULTC_TAG_BYTES] = {0};

    ASSERT_EQ(crypto_encrypt(NULL, 16, key, nonce, buf, tag),
              VAULTC_ERR_INVALID_ARG);
    ASSERT_EQ(crypto_encrypt(buf, 16, NULL, nonce, buf, tag),
              VAULTC_ERR_INVALID_ARG);
    ASSERT_EQ(crypto_encrypt(buf, 16, key, NULL, buf, tag),
              VAULTC_ERR_INVALID_ARG);
    ASSERT_EQ(crypto_encrypt(buf, 16, key, nonce, NULL, tag),
              VAULTC_ERR_INVALID_ARG);
    ASSERT_EQ(crypto_encrypt(buf, 16, key, nonce, buf, NULL),
              VAULTC_ERR_INVALID_ARG);
}

/* ── Test: crypto_decrypt rejects NULL arguments ────────────────────────────── */

TEST(test_decrypt_null_args)
{
    uint8_t key[VAULTC_KEY_BYTES] = {0};
    uint8_t nonce[VAULTC_NONCE_BYTES] = {0};
    uint8_t buf[16] = {0};
    uint8_t tag[VAULTC_TAG_BYTES] = {0};

    ASSERT_EQ(crypto_decrypt(NULL, 16, key, nonce, tag, buf),
              VAULTC_ERR_INVALID_ARG);
    ASSERT_EQ(crypto_decrypt(buf, 16, NULL, nonce, tag, buf),
              VAULTC_ERR_INVALID_ARG);
    ASSERT_EQ(crypto_decrypt(buf, 16, key, NULL, tag, buf),
              VAULTC_ERR_INVALID_ARG);
    ASSERT_EQ(crypto_decrypt(buf, 16, key, nonce, NULL, buf),
              VAULTC_ERR_INVALID_ARG);
    ASSERT_EQ(crypto_decrypt(buf, 16, key, nonce, tag, NULL),
              VAULTC_ERR_INVALID_ARG);
}

/* ── Test: crypto_secure_zero actually zeroes memory ────────────────────────── */

TEST(test_secure_zero)
{
    uint8_t buf[32];
    memset(buf, 0xFF, sizeof(buf));

    crypto_secure_zero(buf, sizeof(buf));

    ASSERT_MEM_ZERO(buf, sizeof(buf));
}

/* ── main ───────────────────────────────────────────────────────────────────── */

int main(void)
{
    RUN_TEST(test_crypto_init_succeeds);
    RUN_TEST(test_crypto_init_idempotent);
    RUN_TEST(test_derive_key_deterministic);
    RUN_TEST(test_derive_key_avalanche);
    RUN_TEST(test_derive_key_null_args);
    RUN_TEST(test_encrypt_decrypt_roundtrip);
    RUN_TEST(test_decrypt_wrong_key_fails);
    RUN_TEST(test_decrypt_tampered_ciphertext_fails);
    RUN_TEST(test_random_bytes_not_all_zero);
    RUN_TEST(test_random_bytes_null_arg);
    RUN_TEST(test_encrypt_null_args);
    RUN_TEST(test_decrypt_null_args);
    RUN_TEST(test_secure_zero);
    PRINT_RESULTS();
    return g_tests_failed > 0 ? 1 : 0;
}
