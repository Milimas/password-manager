/*
 * VaultC — Cryptographic Operations (libsodium wrapper)
 * File: src/core/crypto.c
 */

#include "vaultc/crypto.h"

#include <string.h>

#include <sodium.h>

VaultcError crypto_init(void)
{
    if (sodium_init() == -1)
    {
        return VAULTC_ERR_CRYPTO;
    }
    return VAULTC_OK;
}

VaultcError crypto_derive_key(const char *password,
                              const uint8_t salt[VAULTC_SALT_BYTES],
                              uint32_t ops,
                              uint32_t mem,
                              uint8_t key_out[VAULTC_KEY_BYTES])
{
    if (password == NULL || salt == NULL || key_out == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    int rc = crypto_pwhash(key_out,
                           VAULTC_KEY_BYTES,
                           password,
                           strlen(password),
                           salt,
                           (unsigned long long)ops,
                           (size_t)mem,
                           crypto_pwhash_ALG_ARGON2ID13);
    if (rc != 0)
    {
        sodium_memzero(key_out, VAULTC_KEY_BYTES);
        return VAULTC_ERR_CRYPTO;
    }

    return VAULTC_OK;
}

VaultcError crypto_encrypt(const uint8_t *plaintext,
                           size_t plaintext_len,
                           const uint8_t key[VAULTC_KEY_BYTES],
                           const uint8_t nonce[VAULTC_NONCE_BYTES],
                           uint8_t *ciphertext_out,
                           uint8_t tag_out[VAULTC_TAG_BYTES])
{
    if (plaintext == NULL || key == NULL || nonce == NULL ||
        ciphertext_out == NULL || tag_out == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    unsigned long long tag_len = 0;

    int rc = crypto_aead_aes256gcm_encrypt_detached(
        ciphertext_out,
        tag_out,
        &tag_len,
        plaintext,
        (unsigned long long)plaintext_len,
        NULL, /* no additional data */
        0,    /* additional data length */
        NULL, /* nsec — unused in AES-GCM */
        nonce,
        key);

    if (rc != 0)
    {
        return VAULTC_ERR_CRYPTO;
    }

    return VAULTC_OK;
}

VaultcError crypto_decrypt(const uint8_t *ciphertext,
                           size_t ciphertext_len,
                           const uint8_t key[VAULTC_KEY_BYTES],
                           const uint8_t nonce[VAULTC_NONCE_BYTES],
                           const uint8_t tag[VAULTC_TAG_BYTES],
                           uint8_t *plaintext_out)
{
    if (ciphertext == NULL || key == NULL || nonce == NULL ||
        tag == NULL || plaintext_out == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    int rc = crypto_aead_aes256gcm_decrypt_detached(
        plaintext_out,
        NULL, /* nsec — unused in AES-GCM */
        ciphertext,
        (unsigned long long)ciphertext_len,
        tag,
        NULL, /* no additional data */
        0,    /* additional data length */
        nonce,
        key);

    if (rc != 0)
    {
        /* Tag verification failed: wrong key or tampered data */
        return VAULTC_ERR_BAD_PASSWORD;
    }

    return VAULTC_OK;
}

VaultcError crypto_random_bytes(uint8_t *buf, size_t len)
{
    if (buf == NULL)
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    randombytes_buf(buf, len);
    return VAULTC_OK;
}

void crypto_secure_zero(void *buf, size_t len)
{
    if (buf != NULL)
    {
        sodium_memzero(buf, len);
    }
}
