/*
 * VaultC — Cryptographic Operations
 * File: include/vaultc/crypto.h
 */

#ifndef VAULTC_CRYPTO_H
#define VAULTC_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#include "vaultc/types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /* --- Constants --- */

#define VAULTC_KEY_BYTES 32
#define VAULTC_SALT_BYTES 32
#define VAULTC_NONCE_BYTES 12 /* crypto_aead_aes256gcm_NPUBBYTES */
#define VAULTC_TAG_BYTES 16   /* crypto_aead_aes256gcm_ABYTES    */

    /**
     * Initialize the cryptographic subsystem (libsodium).
     * Must be called once before any other crypto_* function.
     *
     * @return VAULTC_OK on success, VAULTC_ERR_CRYPTO if libsodium
     *         initialization fails.
     */
    VaultcError crypto_init(void);

    /**
     * Derive a 256-bit encryption key from a master password using Argon2id.
     *
     * @param password  Null-terminated master password string.
     * @param salt      Random salt (VAULTC_SALT_BYTES bytes).
     * @param ops       Argon2id ops_limit (computational cost).
     * @param mem       Argon2id mem_limit in bytes (memory cost).
     * @param key_out   Output buffer for derived key (VAULTC_KEY_BYTES bytes).
     *                  Caller owns this buffer and MUST zero it after use.
     *
     * @return VAULTC_OK on success,
     *         VAULTC_ERR_INVALID_ARG if any pointer is NULL,
     *         VAULTC_ERR_CRYPTO on KDF failure.
     */
    VaultcError crypto_derive_key(const char *password,
                                  const uint8_t salt[VAULTC_SALT_BYTES],
                                  uint32_t ops,
                                  uint32_t mem,
                                  uint8_t key_out[VAULTC_KEY_BYTES]);

    /**
     * Encrypt plaintext using AES-256-GCM in detached mode.
     *
     * @param plaintext       Input plaintext buffer.
     * @param plaintext_len   Length of plaintext in bytes.
     * @param key             256-bit encryption key (VAULTC_KEY_BYTES bytes).
     * @param nonce           Nonce (VAULTC_NONCE_BYTES bytes). MUST be unique
     *                        per encryption with the same key.
     * @param ciphertext_out  Output buffer for ciphertext. Must be at least
     *                        plaintext_len bytes. Caller owns this buffer.
     * @param tag_out         Output buffer for GCM authentication tag
     *                        (VAULTC_TAG_BYTES bytes).
     *
     * @return VAULTC_OK on success,
     *         VAULTC_ERR_INVALID_ARG if any pointer is NULL,
     *         VAULTC_ERR_CRYPTO on encryption failure.
     */
    VaultcError crypto_encrypt(const uint8_t *plaintext,
                               size_t plaintext_len,
                               const uint8_t key[VAULTC_KEY_BYTES],
                               const uint8_t nonce[VAULTC_NONCE_BYTES],
                               uint8_t *ciphertext_out,
                               uint8_t tag_out[VAULTC_TAG_BYTES]);

    /**
     * Decrypt ciphertext using AES-256-GCM in detached mode.
     *
     * @param ciphertext       Input ciphertext buffer.
     * @param ciphertext_len   Length of ciphertext in bytes.
     * @param key              256-bit encryption key (VAULTC_KEY_BYTES bytes).
     * @param nonce            Nonce used during encryption (VAULTC_NONCE_BYTES).
     * @param tag              GCM authentication tag (VAULTC_TAG_BYTES bytes).
     * @param plaintext_out    Output buffer for decrypted plaintext. Must be at
     *                         least ciphertext_len bytes. Caller owns this buffer.
     *
     * @return VAULTC_OK on success,
     *         VAULTC_ERR_INVALID_ARG if any pointer is NULL,
     *         VAULTC_ERR_BAD_PASSWORD if authentication tag verification fails
     *         (wrong key or tampered ciphertext).
     */
    VaultcError crypto_decrypt(const uint8_t *ciphertext,
                               size_t ciphertext_len,
                               const uint8_t key[VAULTC_KEY_BYTES],
                               const uint8_t nonce[VAULTC_NONCE_BYTES],
                               const uint8_t tag[VAULTC_TAG_BYTES],
                               uint8_t *plaintext_out);

    /**
     * Fill a buffer with cryptographically secure random bytes.
     *
     * @param buf  Output buffer.
     * @param len  Number of random bytes to generate.
     *
     * @return VAULTC_OK on success,
     *         VAULTC_ERR_INVALID_ARG if buf is NULL.
     */
    VaultcError crypto_random_bytes(uint8_t *buf, size_t len);

    /**
     * Securely zero a memory buffer. Uses sodium_memzero which the
     * compiler cannot optimize away.
     *
     * @param buf  Buffer to zero.
     * @param len  Number of bytes to zero.
     *
     * @warning Always use this instead of memset for sensitive data
     *          (passwords, keys, plaintext).
     */
    void crypto_secure_zero(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VAULTC_CRYPTO_H */
