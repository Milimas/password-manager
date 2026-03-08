/*
 * VaultC — Crypto Layer Tests
 * File: tests/test_crypto.c
 */

#include "harness.h"
#include "vaultc/types.h"

TEST(test_placeholder)
{
    ASSERT_TRUE(1);
}

int main(void)
{
    RUN_TEST(test_placeholder);
    PRINT_RESULTS();
    return g_tests_failed > 0 ? 1 : 0;
}
