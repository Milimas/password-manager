/*
 * VaultC — Password Generator
 * File: src/generator/pwgen.c
 */

#include "vaultc/pwgen.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "vaultc/crypto.h"

/* ── Character class definitions ───────────────────────────────────────────── */

static const char UPPERCASE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char LOWERCASE[] = "abcdefghijklmnopqrstuvwxyz";
static const char DIGITS[]    = "0123456789";
static const char SYMBOLS[]   = "!@#$%^&*()-_=+[]{}<>,.?/|~";

#define UPPERCASE_LEN 26
#define LOWERCASE_LEN 26
#define DIGITS_LEN    10
#define SYMBOLS_LEN   26

/* ── Internal: check if a character is in a string ─────────────────────────── */

static int char_in(char c, const char *set, size_t set_len)
{
    for (size_t i = 0; i < set_len; i++)
    {
        if (set[i] == c)
        {
            return 1;
        }
    }
    return 0;
}

/* ── Internal: check if a character should be excluded ─────────────────────── */

static int is_excluded(char c, const char *exclude)
{
    if (exclude == NULL)
    {
        return 0;
    }
    while (*exclude)
    {
        if (*exclude == c)
        {
            return 1;
        }
        exclude++;
    }
    return 0;
}

/* ── Internal: build the charset from options, returns charset length ──────── */

static size_t build_charset(const PwgenOptions *opts, char *charset,
                            size_t charset_cap)
{
    size_t len = 0;

    if (opts->use_uppercase)
    {
        for (size_t i = 0; i < UPPERCASE_LEN && len < charset_cap; i++)
        {
            if (!is_excluded(UPPERCASE[i], opts->exclude_chars))
            {
                charset[len++] = UPPERCASE[i];
            }
        }
    }

    if (opts->use_lowercase)
    {
        for (size_t i = 0; i < LOWERCASE_LEN && len < charset_cap; i++)
        {
            if (!is_excluded(LOWERCASE[i], opts->exclude_chars))
            {
                charset[len++] = LOWERCASE[i];
            }
        }
    }

    if (opts->use_digits)
    {
        for (size_t i = 0; i < DIGITS_LEN && len < charset_cap; i++)
        {
            if (!is_excluded(DIGITS[i], opts->exclude_chars))
            {
                charset[len++] = DIGITS[i];
            }
        }
    }

    if (opts->use_symbols)
    {
        for (size_t i = 0; i < SYMBOLS_LEN && len < charset_cap; i++)
        {
            if (!is_excluded(SYMBOLS[i], opts->exclude_chars))
            {
                charset[len++] = SYMBOLS[i];
            }
        }
    }

    return len;
}

/* ── Internal: buffered random byte source ─────────────────────────────────── */

#define RAND_BUF_SIZE 256

static uint8_t g_rand_buf[RAND_BUF_SIZE];
static size_t  g_rand_pos = RAND_BUF_SIZE; /* force initial fill */

static uint8_t next_random_byte(void)
{
    if (g_rand_pos >= RAND_BUF_SIZE)
    {
        crypto_random_bytes(g_rand_buf, RAND_BUF_SIZE);
        g_rand_pos = 0;
    }
    return g_rand_buf[g_rand_pos++];
}

/* ── Internal: pick a random index using rejection sampling ────────────────── */

static size_t random_index(size_t charset_len)
{
    /*
     * Rejection sampling to avoid modulo bias.
     * Find the largest multiple of charset_len that fits in [1..256].
     * Discard any random byte >= that threshold.
     *
     * NOTE: We must NOT write (256 - (256 % charset_len)) because when
     * charset_len is a power-of-two divisor of 256 the result is 256,
     * which truncates to 0 in a uint8_t → infinite loop.
     */
    unsigned threshold = (256u / (unsigned)charset_len) * (unsigned)charset_len;

    for (;;)
    {
        uint8_t byte = next_random_byte();
        if (byte < threshold)
        {
            return (size_t)(byte % charset_len);
        }
    }
}

/* ── Internal: count characters from a class in a string ───────────────────── */

static int count_class(const char *pw, size_t pw_len,
                       const char *class_chars, size_t class_len)
{
    int n = 0;
    for (size_t i = 0; i < pw_len; i++)
    {
        if (char_in(pw[i], class_chars, class_len))
        {
            n++;
        }
    }
    return n;
}

/* ── Internal: check if password meets minimum requirements ────────────────── */

static int meets_requirements(const char *pw, size_t pw_len,
                              const PwgenOptions *opts)
{
    if (opts->min_uppercase > 0)
    {
        if (count_class(pw, pw_len, UPPERCASE, UPPERCASE_LEN) <
            opts->min_uppercase)
        {
            return 0;
        }
    }

    if (opts->min_digits > 0)
    {
        if (count_class(pw, pw_len, DIGITS, DIGITS_LEN) < opts->min_digits)
        {
            return 0;
        }
    }

    if (opts->min_symbols > 0)
    {
        if (count_class(pw, pw_len, SYMBOLS, SYMBOLS_LEN) < opts->min_symbols)
        {
            return 0;
        }
    }

    return 1;
}

/* ── Internal: Fisher-Yates shuffle using crypto_random_bytes ──────────────── */

static void fisher_yates_shuffle(char *buf, size_t len)
{
    if (len <= 1)
    {
        return;
    }

    for (size_t i = len - 1; i > 0; i--)
    {
        size_t j = random_index(i + 1);
        char tmp = buf[i];
        buf[i] = buf[j];
        buf[j] = tmp;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

char *pwgen_generate(const PwgenOptions *opts)
{
    if (opts == NULL)
    {
        return NULL;
    }

    if (opts->length < 1 || opts->length > 128)
    {
        return NULL;
    }

    /* Build the charset */
    char charset[256];
    size_t charset_len = build_charset(opts, charset, sizeof(charset));

    if (charset_len == 0)
    {
        return NULL; /* No character classes enabled */
    }

    size_t pw_len = (size_t)opts->length;
    char *pw = malloc(pw_len + 1);
    if (pw == NULL)
    {
        return NULL;
    }

    /*
     * Generate passwords until one meets all minimum requirements.
     * With reasonable constraints this converges very quickly.
     */
    for (;;)
    {
        for (size_t i = 0; i < pw_len; i++)
        {
            pw[i] = charset[random_index(charset_len)];
        }
        pw[pw_len] = '\0';

        if (meets_requirements(pw, pw_len, opts))
        {
            break;
        }
    }

    /* Fisher-Yates shuffle for extra diffusion */
    fisher_yates_shuffle(pw, pw_len);

    return pw;
}

double pwgen_entropy_bits(const char *password)
{
    if (password == NULL || password[0] == '\0')
    {
        return 0.0;
    }

    size_t len = strlen(password);
    int has_lower = 0;
    int has_upper = 0;
    int has_digit = 0;
    int has_symbol = 0;

    for (size_t i = 0; i < len; i++)
    {
        char c = password[i];
        if (c >= 'a' && c <= 'z')
        {
            has_lower = 1;
        }
        else if (c >= 'A' && c <= 'Z')
        {
            has_upper = 1;
        }
        else if (c >= '0' && c <= '9')
        {
            has_digit = 1;
        }
        else
        {
            has_symbol = 1;
        }
    }

    int charset_size = 0;
    if (has_lower)
    {
        charset_size += 26;
    }
    if (has_upper)
    {
        charset_size += 26;
    }
    if (has_digit)
    {
        charset_size += 10;
    }
    if (has_symbol)
    {
        charset_size += 32; /* Approximate printable symbol count */
    }

    if (charset_size == 0)
    {
        return 0.0;
    }

    return log2((double)charset_size) * (double)len;
}

StrengthScore pwgen_check_strength(const char *password)
{
    double bits = pwgen_entropy_bits(password);

    if (bits >= 128.0)
    {
        return STRENGTH_VERY_STRONG;
    }
    if (bits >= 60.0)
    {
        return STRENGTH_STRONG;
    }
    if (bits >= 36.0)
    {
        return STRENGTH_FAIR;
    }
    if (bits >= 28.0)
    {
        return STRENGTH_WEAK;
    }
    return STRENGTH_VERY_WEAK;
}
