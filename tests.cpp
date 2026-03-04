/**
 * Copyright (c) 2026 Bivex
 *
 * Author: Bivex
 * Available for contact via email: support@b-b.top
 * For up-to-date contact information:
 * https://github.com/bivex
 *
 * Created: 2026-03-04 15:11
 * Last Updated: 2026-03-04 15:11
 *
 * Licensed under the MIT License.
 * Commercial licensing available upon request.
 */

/**
 * @file tests.cpp
 * @brief Test suite for encrypted_string.h
 */

#include "encrypted_string.h"
#include <iostream>
#include <cstdint>
#include <cstring>

// Test macro: creates a test function
#define DEFINE_ENC_TEST(name, literal) \
    void test_##name() { \
        constexpr auto enc = ENC_STR(literal); \
        constexpr std::size_t literal_len = sizeof(literal) - 1U; \
        \
        if (literal_len > 0U) { \
            const bool obf = enc.is_obfuscated_against(literal, literal_len); \
            if (!obf) { \
                std::cerr << "FAILED: String must be obfuscated in binary" << std::endl; \
                std::exit(1); \
            } \
        } \
        \
        { \
            strenc::DecryptGuard<256U> g(enc.data(), enc.size(), enc.key_); \
            const int cmp_result = std::strcmp(g.c_str(), literal); \
            if (cmp_result != 0) { \
                std::cerr << "FAILED: Decrypted value must match original" << std::endl; \
                std::exit(1); \
            } \
        } \
        \
        if (literal_len > 0U) { \
            const bool obf2 = enc.is_obfuscated_against(literal, literal_len); \
            if (!obf2) { \
                std::cerr << "FAILED: Encrypted data must remain obfuscated" << std::endl; \
                std::exit(1); \
            } \
        } \
    }

// Test cases
DEFINE_ENC_TEST(hello, "Hello, world!")
DEFINE_ENC_TEST(empty, "")

int main() {
    test_hello();
    test_empty();
    std::cout << "All encrypt/decrypt tests passed\n";
    return 0;
}
