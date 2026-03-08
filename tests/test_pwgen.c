/*
 * VaultC — Password Generator Tests
 * File: tests/test_pwgen.c
 */

#include "harness.h"
#include "vaultc/types.h"
#include "vaultc/pwgen.h"
#include "vaultc/crypto.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── Helpers ───────────────────────────────────────────────────────────────── */

static PwgenOptions default_opts(void)
{
    PwgenOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.length        = 20;
    opts.use_uppercase = true;
    opts.use_lowercase = true;
    opts.use_digits    = true;
    opts.use_symbols   = true;
    opts.exclude_chars = NULL;
    opts.min_uppercase = 0;
    opts.min_digits    = 0;
    opts.min_symbols   = 0;
    return opts;
}

static int is_digit(char c) { return c >= '0' && c <= '9'; }
static int is_upper(char c) { return c >= 'A' && c <= 'Z'; }
static int is_lower(char c) { return c >= 'a' && c <= 'z'; }

static int is_symbol(char c)
{
    return !is_digit(c) && !is_upper(c) && !is_lower(c) && c != '\0';
}

/* ── Tests ─────────────────────────────────────────────────────────────────── */

TEST(test_generate_length_matches)
{
    ASSERT_EQ(crypto_init(), VAULTC_OK);

    PwgenOptions opts = default_opts();
    int lengths[] = {1, 4, 8, 16, 32, 64, 128};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
    {
        opts.length = lengths[i];
        char *pw = pwgen_generate(&opts);
        ASSERT_NOT_NULL(pw);
        ASSERT_EQ((int)strlen(pw), lengths[i]);
        crypto_secure_zero(pw, strlen(pw));
        free(pw);
    }
}

TEST(test_generate_digits_only)
{
    PwgenOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.length        = 30;
    opts.use_uppercase = false;
    opts.use_lowercase = false;
    opts.use_digits    = true;
    opts.use_symbols   = false;

    char *pw = pwgen_generate(&opts);
    ASSERT_NOT_NULL(pw);
    ASSERT_EQ((int)strlen(pw), 30);

    for (int i = 0; i < 30; i++)
    {
        ASSERT_TRUE(is_digit(pw[i]));
    }

    crypto_secure_zero(pw, strlen(pw));
    free(pw);
}

TEST(test_generate_lowercase_only)
{
    PwgenOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.length        = 30;
    opts.use_uppercase = false;
    opts.use_lowercase = true;
    opts.use_digits    = false;
    opts.use_symbols   = false;

    char *pw = pwgen_generate(&opts);
    ASSERT_NOT_NULL(pw);

    for (int i = 0; i < 30; i++)
    {
        ASSERT_TRUE(is_lower(pw[i]));
    }

    crypto_secure_zero(pw, strlen(pw));
    free(pw);
}

TEST(test_generate_all_classes_present)
{
    PwgenOptions opts = default_opts();
    opts.length = 40;
    opts.min_uppercase = 1;
    opts.min_digits    = 1;
    opts.min_symbols   = 1;

    char *pw = pwgen_generate(&opts);
    ASSERT_NOT_NULL(pw);
    ASSERT_EQ((int)strlen(pw), 40);

    int has_upper = 0, has_lower = 0, has_digit = 0, has_sym = 0;
    for (size_t i = 0; i < strlen(pw); i++)
    {
        if (is_upper(pw[i]))  has_upper = 1;
        if (is_lower(pw[i]))  has_lower = 1;
        if (is_digit(pw[i]))  has_digit = 1;
        if (is_symbol(pw[i])) has_sym   = 1;
    }

    ASSERT_TRUE(has_upper);
    ASSERT_TRUE(has_lower);
    ASSERT_TRUE(has_digit);
    ASSERT_TRUE(has_sym);

    crypto_secure_zero(pw, strlen(pw));
    free(pw);
}

TEST(test_generate_min_constraints)
{
    PwgenOptions opts = default_opts();
    opts.length        = 20;
    opts.min_uppercase = 5;
    opts.min_digits    = 5;
    opts.min_symbols   = 3;

    char *pw = pwgen_generate(&opts);
    ASSERT_NOT_NULL(pw);

    int up = 0, dig = 0, sym = 0;
    for (size_t i = 0; i < strlen(pw); i++)
    {
        if (is_upper(pw[i]))  up++;
        if (is_digit(pw[i]))  dig++;
        if (is_symbol(pw[i])) sym++;
    }

    ASSERT_TRUE(up  >= 5);
    ASSERT_TRUE(dig >= 5);
    ASSERT_TRUE(sym >= 3);

    crypto_secure_zero(pw, strlen(pw));
    free(pw);
}

TEST(test_generate_exclude_chars)
{
    PwgenOptions opts = default_opts();
    opts.length        = 50;
    opts.exclude_chars = "aeiouAEIOU0O1lI";

    char *pw = pwgen_generate(&opts);
    ASSERT_NOT_NULL(pw);

    for (size_t i = 0; i < strlen(pw); i++)
    {
        const char *exc = opts.exclude_chars;
        while (*exc)
        {
            ASSERT_TRUE(pw[i] != *exc);
            exc++;
        }
    }

    crypto_secure_zero(pw, strlen(pw));
    free(pw);
}

TEST(test_generate_null_opts_returns_null)
{
    char *pw = pwgen_generate(NULL);
    ASSERT_NULL(pw);
}

TEST(test_generate_no_classes_returns_null)
{
    PwgenOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.length = 16;
    /* All use_* false → empty charset */

    char *pw = pwgen_generate(&opts);
    ASSERT_NULL(pw);
}

TEST(test_generate_invalid_length_returns_null)
{
    PwgenOptions opts = default_opts();

    opts.length = 0;
    ASSERT_NULL(pwgen_generate(&opts));

    opts.length = 129;
    ASSERT_NULL(pwgen_generate(&opts));
}

TEST(test_entropy_bits_digits_only)
{
    /* 10-digit numeric: log2(10) * 10 ≈ 33.22 */
    double bits = pwgen_entropy_bits("1234567890");
    ASSERT_TRUE(bits > 33.0);
    ASSERT_TRUE(bits < 34.0);
}

TEST(test_entropy_bits_all_classes)
{
    /* "aA1!" → charset = 26+26+10+32 = 94 → log2(94)*4 ≈ 26.24 */
    double bits = pwgen_entropy_bits("aA1!");
    ASSERT_TRUE(bits > 26.0);
    ASSERT_TRUE(bits < 27.0);
}

TEST(test_entropy_bits_empty_and_null)
{
    ASSERT_TRUE(pwgen_entropy_bits(NULL) == 0.0);
    ASSERT_TRUE(pwgen_entropy_bits("") == 0.0);
}

TEST(test_check_strength_thresholds)
{
    /* Very weak: "ab" → log2(26)*2 ≈ 9.4 */
    ASSERT_EQ(pwgen_check_strength("ab"), STRENGTH_VERY_WEAK);

    /* Weak: "abcdef" → log2(26)*6 ≈ 28.2 */
    ASSERT_EQ(pwgen_check_strength("abcdef"), STRENGTH_WEAK);

    /* Fair: "abcdefghij" → log2(26)*10 ≈ 47.0 */
    ASSERT_EQ(pwgen_check_strength("abcdefghij"), STRENGTH_FAIR);

    /* Strong: "aA1!aA1!aA1!" → log2(94)*12 ≈ 78.7 */
    ASSERT_EQ(pwgen_check_strength("aA1!aA1!aA1!"), STRENGTH_STRONG);

    /* Very strong: long password */
    ASSERT_EQ(pwgen_check_strength(
        "aA1!bB2@cC3#dD4$eE5%fF6^"), STRENGTH_VERY_STRONG);
}

TEST(test_1000_unique_passwords)
{
    PwgenOptions opts = default_opts();
    opts.length = 24;

    #define N_PASSWORDS 1000
    char *passwords[N_PASSWORDS];

    for (int i = 0; i < N_PASSWORDS; i++)
    {
        passwords[i] = pwgen_generate(&opts);
        ASSERT_NOT_NULL(passwords[i]);
        ASSERT_EQ((int)strlen(passwords[i]), 24);
    }

    /* Birthday check: no two identical */
    int collision = 0;
    for (int i = 0; i < N_PASSWORDS && !collision; i++)
    {
        for (int j = i + 1; j < N_PASSWORDS && !collision; j++)
        {
            if (strcmp(passwords[i], passwords[j]) == 0)
            {
                collision = 1;
            }
        }
    }
    ASSERT_FALSE(collision);

    for (int i = 0; i < N_PASSWORDS; i++)
    {
        crypto_secure_zero(passwords[i], (size_t)opts.length);
        free(passwords[i]);
    }
    #undef N_PASSWORDS
}

/* ── Runner ────────────────────────────────────────────────────────────────── */

int main(void)
{
    RUN_TEST(test_generate_length_matches);
    RUN_TEST(test_generate_digits_only);
    RUN_TEST(test_generate_lowercase_only);
    RUN_TEST(test_generate_all_classes_present);
    RUN_TEST(test_generate_min_constraints);
    RUN_TEST(test_generate_exclude_chars);
    RUN_TEST(test_generate_null_opts_returns_null);
    RUN_TEST(test_generate_no_classes_returns_null);
    RUN_TEST(test_generate_invalid_length_returns_null);
    RUN_TEST(test_entropy_bits_digits_only);
    RUN_TEST(test_entropy_bits_all_classes);
    RUN_TEST(test_entropy_bits_empty_and_null);
    RUN_TEST(test_check_strength_thresholds);
    RUN_TEST(test_1000_unique_passwords);
    PRINT_RESULTS();
    return g_tests_failed > 0 ? 1 : 0;
}
