/*
 * VaultC — TOTP Code Generation (RFC 6238)
 * File: src/utils/totp.c
 *
 * Implements HMAC-SHA1 internally since libsodium does not provide it.
 * SHA-1 is used only for TOTP compatibility — not for security hashing.
 */

#include "vaultc/utils.h"

#include <string.h>
#include <stdio.h>
#include <time.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * SHA-1 Implementation (RFC 3174)
 *
 * Used exclusively for HMAC-SHA1 in TOTP. Not for general hashing.
 * ═══════════════════════════════════════════════════════════════════════════ */

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

typedef struct
{
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[SHA1_BLOCK_SIZE];
} Sha1Ctx;

static uint32_t sha1_rotl(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static void sha1_transform(Sha1Ctx *ctx, const uint8_t block[64])
{
    uint32_t w[80];

    for (int i = 0; i < 16; i++)
    {
        w[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++)
    {
        w[i] = sha1_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];

    for (int i = 0; i < 80; i++)
    {
        uint32_t f, k;
        if (i < 20)
        {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999U;
        }
        else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1U;
        }
        else if (i < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCU;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xCA62C1D6U;
        }

        uint32_t temp = sha1_rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = sha1_rotl(b, 30);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_init(Sha1Ctx *ctx)
{
    ctx->state[0] = 0x67452301U;
    ctx->state[1] = 0xEFCDAB89U;
    ctx->state[2] = 0x98BADCFEU;
    ctx->state[3] = 0x10325476U;
    ctx->state[4] = 0xC3D2E1F0U;
    ctx->count = 0;
    memset(ctx->buffer, 0, SHA1_BLOCK_SIZE);
}

static void sha1_update(Sha1Ctx *ctx, const uint8_t *data, size_t len)
{
    size_t buf_used = (size_t)(ctx->count % SHA1_BLOCK_SIZE);
    ctx->count += len;

    size_t i = 0;
    if (buf_used > 0)
    {
        size_t space = SHA1_BLOCK_SIZE - buf_used;
        size_t take = len < space ? len : space;
        memcpy(ctx->buffer + buf_used, data, take);
        i = take;
        if (buf_used + take < SHA1_BLOCK_SIZE)
        {
            return;
        }
        sha1_transform(ctx, ctx->buffer);
    }

    for (; i + SHA1_BLOCK_SIZE <= len; i += SHA1_BLOCK_SIZE)
    {
        sha1_transform(ctx, data + i);
    }

    if (i < len)
    {
        memcpy(ctx->buffer, data + i, len - i);
    }
}

static void sha1_final(Sha1Ctx *ctx, uint8_t digest[SHA1_DIGEST_SIZE])
{
    uint64_t bit_count = ctx->count * 8;
    size_t buf_used = (size_t)(ctx->count % SHA1_BLOCK_SIZE);

    /* Append 0x80 padding byte */
    ctx->buffer[buf_used++] = 0x80;

    if (buf_used > 56)
    {
        memset(ctx->buffer + buf_used, 0, SHA1_BLOCK_SIZE - buf_used);
        sha1_transform(ctx, ctx->buffer);
        buf_used = 0;
    }

    memset(ctx->buffer + buf_used, 0, 56 - buf_used);

    /* Append 64-bit big-endian bit count */
    for (int i = 0; i < 8; i++)
    {
        ctx->buffer[56 + i] = (uint8_t)(bit_count >> (56 - i * 8));
    }

    sha1_transform(ctx, ctx->buffer);

    /* Write digest in big-endian */
    for (int i = 0; i < 5; i++)
    {
        digest[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HMAC-SHA1 (RFC 2104)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void hmac_sha1(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t out[SHA1_DIGEST_SIZE])
{
    uint8_t k_pad[SHA1_BLOCK_SIZE];
    Sha1Ctx ctx;

    /* If key is longer than block size, hash it first */
    uint8_t key_hash[SHA1_DIGEST_SIZE];
    if (key_len > SHA1_BLOCK_SIZE)
    {
        sha1_init(&ctx);
        sha1_update(&ctx, key, key_len);
        sha1_final(&ctx, key_hash);
        key = key_hash;
        key_len = SHA1_DIGEST_SIZE;
    }

    /* Inner pad: key XOR 0x36 */
    memset(k_pad, 0x36, SHA1_BLOCK_SIZE);
    for (size_t i = 0; i < key_len; i++)
    {
        k_pad[i] ^= key[i];
    }

    sha1_init(&ctx);
    sha1_update(&ctx, k_pad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, msg, msg_len);

    uint8_t inner_hash[SHA1_DIGEST_SIZE];
    sha1_final(&ctx, inner_hash);

    /* Outer pad: key XOR 0x5C */
    memset(k_pad, 0x5C, SHA1_BLOCK_SIZE);
    for (size_t i = 0; i < key_len; i++)
    {
        k_pad[i] ^= key[i];
    }

    sha1_init(&ctx);
    sha1_update(&ctx, k_pad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, inner_hash, SHA1_DIGEST_SIZE);
    sha1_final(&ctx, out);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Base32 Decoder (RFC 4648)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int base32_decode_char(char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z')
    {
        return c - 'a';
    }
    if (c >= '2' && c <= '7')
    {
        return c - '2' + 26;
    }
    return -1; /* Invalid or padding '=' */
}

/**
 * Decode a Base32 string into raw bytes.
 *
 * @param input    Null-terminated Base32 string (may include '=' padding).
 * @param out      Output buffer (must be at least (strlen(input)*5/8) bytes).
 * @param out_len  Receives the number of decoded bytes.
 * @return         0 on success, -1 on invalid input.
 */
static int base32_decode(const char *input, uint8_t *out, size_t *out_len)
{
    size_t len = strlen(input);
    size_t bits = 0;
    int buffer = 0;
    size_t written = 0;

    for (size_t i = 0; i < len; i++)
    {
        if (input[i] == '=' || input[i] == ' ')
        {
            continue; /* Skip padding and whitespace */
        }

        int val = base32_decode_char(input[i]);
        if (val < 0)
        {
            return -1;
        }

        buffer = (buffer << 5) | val;
        bits += 5;

        if (bits >= 8)
        {
            bits -= 8;
            out[written++] = (uint8_t)((buffer >> bits) & 0xFF);
        }
    }

    *out_len = written;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * TOTP (RFC 6238) — Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

VaultcError totp_generate(const char *base32_secret, char *out)
{
    if (base32_secret == NULL || out == NULL ||
        base32_secret[0] == '\0')
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    /* Decode the Base32 secret */
    size_t secret_len = strlen(base32_secret);
    size_t max_decoded = (secret_len * 5) / 8 + 1;
    uint8_t decoded[256]; /* TOTP secrets are typically 10-32 bytes */
    if (max_decoded > sizeof(decoded))
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    size_t decoded_len = 0;
    if (base32_decode(base32_secret, decoded, &decoded_len) != 0)
    {
        return VAULTC_ERR_INVALID_ARG;
    }

    /* Calculate time counter: T = floor(time / 30) */
    uint64_t t = (uint64_t)time(NULL) / 30;

    /* Encode counter as 8-byte big-endian */
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--)
    {
        msg[i] = (uint8_t)(t & 0xFF);
        t >>= 8;
    }

    /* HMAC-SHA1(secret, counter) */
    uint8_t hash[SHA1_DIGEST_SIZE];
    hmac_sha1(decoded, decoded_len, msg, sizeof(msg), hash);

    /* Dynamic truncation (RFC 4226 Section 5.4) */
    int offset = hash[SHA1_DIGEST_SIZE - 1] & 0x0F;
    uint32_t code = ((uint32_t)(hash[offset] & 0x7F) << 24) |
                    ((uint32_t)(hash[offset + 1]) << 16) |
                    ((uint32_t)(hash[offset + 2]) << 8) |
                    ((uint32_t)(hash[offset + 3]));

    /* 6-digit code */
    code = code % 1000000;

    snprintf(out, 7, "%06u", code);
    return VAULTC_OK;
}
