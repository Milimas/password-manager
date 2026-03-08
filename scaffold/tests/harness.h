/*
 * VaultC — Minimal Test Harness
 * File: tests/harness.h
 *
 * Usage:
 *   #include "harness.h"
 *
 *   TEST(test_crypto_init) {
 *       ASSERT_EQ(crypto_init(), VAULTC_OK);
 *   }
 *
 *   int main(void) {
 *       RUN_TEST(test_crypto_init);
 *       PRINT_RESULTS();
 *       return g_tests_failed > 0 ? 1 : 0;
 *   }
 */

#ifndef VAULTC_TEST_HARNESS_H
#define VAULTC_TEST_HARNESS_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* --- Global counters --- */
static int g_tests_run    = 0;
static int g_tests_failed = 0;
static int g_current_failed = 0;

/* --- Test definition macro --- */
#define TEST(name) static void name(void)

/* --- Run a test --- */
#define RUN_TEST(name) do {                                          \
    g_tests_run++;                                                   \
    g_current_failed = 0;                                            \
    printf("  [ RUN ] %s\n", #name);                                 \
    name();                                                          \
    if (g_current_failed == 0) {                                     \
        printf("  [ OK  ] %s\n", #name);                            \
    } else {                                                         \
        printf("  [FAIL ] %s\n", #name);                            \
        g_tests_failed++;                                            \
    }                                                                \
} while (0)

/* --- Assertions --- */
#define ASSERT_TRUE(expr) do {                                       \
    if (!(expr)) {                                                   \
        printf("    ASSERT_TRUE failed: %s\n"                        \
               "    at %s:%d\n", #expr, __FILE__, __LINE__);        \
        g_current_failed++;                                          \
        return;                                                      \
    }                                                                \
} while (0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))

#define ASSERT_EQ(a, b) do {                                         \
    if ((a) != (b)) {                                                \
        printf("    ASSERT_EQ failed: %s != %s\n"                   \
               "    at %s:%d\n", #a, #b, __FILE__, __LINE__);      \
        g_current_failed++;                                          \
        return;                                                      \
    }                                                                \
} while (0)

#define ASSERT_NEQ(a, b) do {                                        \
    if ((a) == (b)) {                                                \
        printf("    ASSERT_NEQ failed: %s == %s\n"                  \
               "    at %s:%d\n", #a, #b, __FILE__, __LINE__);      \
        g_current_failed++;                                          \
        return;                                                      \
    }                                                                \
} while (0)

#define ASSERT_NOT_NULL(ptr) do {                                    \
    if ((ptr) == NULL) {                                             \
        printf("    ASSERT_NOT_NULL failed: %s is NULL\n"           \
               "    at %s:%d\n", #ptr, __FILE__, __LINE__);        \
        g_current_failed++;                                          \
        return;                                                      \
    }                                                                \
} while (0)

#define ASSERT_NULL(ptr) do {                                        \
    if ((ptr) != NULL) {                                             \
        printf("    ASSERT_NULL failed: %s is not NULL\n"           \
               "    at %s:%d\n", #ptr, __FILE__, __LINE__);        \
        g_current_failed++;                                          \
        return;                                                      \
    }                                                                \
} while (0)

#define ASSERT_STR_EQ(a, b) do {                                     \
    if (strcmp((a), (b)) != 0) {                                     \
        printf("    ASSERT_STR_EQ failed:\n"                         \
               "      expected: \"%s\"\n"                            \
               "      got:      \"%s\"\n"                            \
               "    at %s:%d\n", (b), (a), __FILE__, __LINE__);    \
        g_current_failed++;                                          \
        return;                                                      \
    }                                                                \
} while (0)

#define ASSERT_MEM_EQ(a, b, len) do {                               \
    if (memcmp((a), (b), (len)) != 0) {                             \
        printf("    ASSERT_MEM_EQ failed: %s != %s (%zu bytes)\n"  \
               "    at %s:%d\n", #a, #b, (size_t)(len),            \
               __FILE__, __LINE__);                                  \
        g_current_failed++;                                          \
        return;                                                      \
    }                                                                \
} while (0)

#define ASSERT_MEM_ZERO(buf, len) do {                               \
    const uint8_t *_b = (const uint8_t *)(buf);                     \
    int _zero = 1;                                                   \
    for (size_t _i = 0; _i < (size_t)(len); _i++) {                \
        if (_b[_i] != 0) { _zero = 0; break; }                     \
    }                                                                \
    if (!_zero) {                                                    \
        printf("    ASSERT_MEM_ZERO failed: %s not zeroed\n"        \
               "    at %s:%d\n", #buf, __FILE__, __LINE__);        \
        g_current_failed++;                                          \
        return;                                                      \
    }                                                                \
} while (0)

/* --- Print summary --- */
#define PRINT_RESULTS() do {                                         \
    printf("\n══════════════════════════════════\n");                \
    printf("  Tests run:    %d\n", g_tests_run);                    \
    printf("  Tests passed: %d\n", g_tests_run - g_tests_failed);   \
    printf("  Tests failed: %d\n", g_tests_failed);                  \
    printf("══════════════════════════════════\n");                  \
    if (g_tests_failed == 0) {                                       \
        printf("  ✓ ALL TESTS PASSED\n");                           \
    } else {                                                         \
        printf("  ✗ SOME TESTS FAILED\n");                          \
    }                                                                \
    printf("══════════════════════════════════\n\n");                \
} while (0)

#endif /* VAULTC_TEST_HARNESS_H */
