/*
 * VaultC — Password Generator
 * File: include/vaultc/pwgen.h
 */

#ifndef VAULTC_PWGEN_H
#define VAULTC_PWGEN_H

#include <stdint.h>
#include <stddef.h>

#include "vaultc/types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /* ═══════════════════════════════════════════════════════════════════════
     * Password Generator
     * ═══════════════════════════════════════════════════════════════════════ */

    /**
     * Generate a random password according to the given options.
     *
     * Uses crypto_random_bytes for all entropy. Applies rejection
     * sampling to avoid modulo bias when mapping random bytes to the
     * charset. Loops until all min_uppercase, min_digits, min_symbols
     * constraints are satisfied.
     *
     * @param opts  Password generation options (length, character classes,
     *              minimum counts). Must not be NULL.
     * @return      Heap-allocated null-terminated password string,
     *              or NULL on invalid options.
     *
     * @warning     The caller MUST call crypto_secure_zero() on the
     *              returned buffer BEFORE free(). Passwords are sensitive
     *              data and must not linger in memory.
     *
     * @code
     *   char *pw = pwgen_generate(&opts);
     *   // ... use pw ...
     *   crypto_secure_zero(pw, strlen(pw));
     *   free(pw);
     * @endcode
     */
    char *pwgen_generate(const PwgenOptions *opts);

    /**
     * Estimate the entropy of a password in bits.
     *
     * Analyses the character classes present in the password to determine
     * the effective charset size, then computes:
     *   entropy = log2(charset_size) * strlen(password)
     *
     * @param password  Null-terminated password string.
     * @return          Estimated entropy in bits, or 0.0 if password is
     *                  NULL or empty.
     */
    double pwgen_entropy_bits(const char *password);

    /**
     * Check the strength of a password based on its estimated entropy.
     *
     * Thresholds:
     *   < 28 bits  → STRENGTH_VERY_WEAK
     *   28–35 bits → STRENGTH_WEAK
     *   36–59 bits → STRENGTH_FAIR
     *   60–127 bits→ STRENGTH_STRONG
     *   128+ bits  → STRENGTH_VERY_STRONG
     *
     * @param password  Null-terminated password string.
     * @return          StrengthScore enum value.
     */
    StrengthScore pwgen_check_strength(const char *password);

#ifdef __cplusplus
}
#endif

#endif /* VAULTC_PWGEN_H */
