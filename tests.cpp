/**
 * Copyright (c) 2026 Bivex
 *
 * Author: Bivex
 * Available for contact via email: support@b-b.top
 * For up-to-date contact information:
 * https://github.com/bivex
 *
 * Created: 2026-03-04 15:52
 * Last Updated: 2026-03-04 15:52
 *
 * Licensed under the MIT License.
 * Commercial licensing available upon request.
 */

// Пример тестов для encrypted_string.h
#include "encrypted_string.h"
#include <iostream>
#include <cassert>
#include <cstring>

// Макрос: определяет тест, использует ENC_STR и AUTO_DECRYPT и делает проверки
#define DEFINE_ENC_TEST(name, literal) \
    void test_##name() { \
        constexpr auto enc = ENC_STR(literal); \
        /* 1) raw bytes differ от оригинала (для непустых строк) */ \
        constexpr size_t literal_len = sizeof(literal) - 1; \
        if (literal_len > 0) { \
            bool obf = enc.is_obfuscated_against(literal, literal_len); \
            assert(obf && "String must be obfuscated in binary"); \
        } \
        /* 2) при расшифровке внутри области - получим исходную строку */ \
        { \
            strenc::DecryptGuard g(enc.data(), enc.size(), enc.key_); \
            assert(std::strcmp(g.c_str(), literal) == 0 && "Decrypted value must match original"); \
        } \
        /* 3) после выхода из области, данные в enc остаются зашифрованными (проверяем снова) */ \
        if (literal_len > 0) { \
            bool obf2 = enc.is_obfuscated_against(literal, literal_len); \
            assert(obf2 && "Encrypted data must remain obfuscated"); \
        } \
    }

// Примеры тестов
DEFINE_ENC_TEST(hello, "Hello, world!");
DEFINE_ENC_TEST(empty, ""); // пустая строка (задача: поддержать)

// Запуск всех тестов
int main() {
    test_hello();
    test_empty();
    std::cout << "All encrypt/decrypt tests passed\n";
    return 0;
}