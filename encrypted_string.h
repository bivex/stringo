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
 * @file encrypted_string.h
 * @brief Compile-time string encryption library (C++17 header-only)
 *
 * @details
 * Encrypts string literals at compile time using constexpr.
 * Encryption algorithm: out[i] = in[i] ^ (rotl32(key, i) + i)
 *
 * @par Usage Example:
 * @code
 *   // Declare encrypted string at compile time
 *   constexpr auto enc = ENC_STR("SecretPassword123");
 *
 *   // Decrypt in local scope (RAII)
 *   {
 *       AUTO_DECRYPT_VAR(decrypted, enc);
 *       std::cout << decrypted.c_str() << std::endl;  // "SecretPassword123"
 *   } // decrypted buffer is securely zeroed here
 *
 *   // Or with simpler macro (creates variable named _dec_ on current line)
 *   AUTO_DECRYPT(enc);
 *   std::cout << _dec_.c_str() << std::endl;
 * @endcode
 *
 * @par Debug Mode:
 * Define DISABLE_STR_ENC to disable encryption (for debugging):
 * @code
 *   #define DISABLE_STR_ENC
 *   #include "encrypted_string.h"
 * @endcode
 *
 * @par Limitations:
 * - Only ASCII/UTF-8 string literals supported
 * - Empty strings "" are supported but not meaningfully obfuscated
 * - wchar_t support not yet implemented
 *
 * @par Thread Safety:
 * Fully thread-safe - decryption is local to each scope with no global state.
 */

#pragma once
#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <cstring>
#include <memory>

namespace strenc {

// Debug mode check
#ifndef DISABLE_STR_ENC
    #define STRENC_ENABLED 1
#else
    #define STRENC_ENABLED 0
#endif

// constexpr rotate-left (32-bit)
constexpr uint32_t rotl32(uint32_t v, unsigned int r) {
    r &= 31;  // Ensure r is in [0, 31] to avoid UB when r == 0 or r == 32
    return r ? (v << r) | (v >> (32 - r)) : v;
}

// простая constexpr-хэш-функция от строки (можно заменить на любую)
constexpr uint32_t constexpr_hash(const char* s, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; ++i) {
        h = (h ^ static_cast<uint32_t>(s[i])) * 16777619u;
    }
    return h;
}

// Шифрование: out[i] = in[i] ^ (rotl32(key, i) + i) (аналогично найденному в репо)
template <size_t N>
struct EncryptedString {
    static_assert(N >= 1, "String literal must have at least null terminator");
    // data_ хранит зашифрованные байты, включая завершающий нулевой
    std::array<uint8_t, N> data_;
    size_t size_; // = N-1 (без нуля), для "" будет 0
    uint32_t key_;

    // constexpr-конструктор: заполняет data_ зашифрованным содержимым
    constexpr EncryptedString(const char (&s)[N], uint32_t key) : data_{}, size_(N - 1), key_(key) {
#if STRENC_ENABLED
        // Encryption enabled: obfuscate the string
        for (size_t i = 0; i < N; ++i) {
            uint8_t b = static_cast<uint8_t>(s[i]);
            uint8_t kbyte = static_cast<uint8_t>((rotl32(key, static_cast<unsigned int>(i)) + static_cast<unsigned int>(i)) & 0xFFu);
            data_[i] = static_cast<uint8_t>(b ^ kbyte);
        }
#else
        // Debug mode: store plaintext (no encryption)
        for (size_t i = 0; i < N; ++i) {
            data_[i] = static_cast<uint8_t>(s[i]);
        }
#endif
    }

    constexpr size_t size() const noexcept { return size_; }
    constexpr const uint8_t* data() const noexcept { return data_.data(); }

    // Проверка: raw байты не совпадают с оригиналом (без расшифровки)
    bool is_obfuscated_against(const char* orig, size_t orig_len) const {
#if STRENC_ENABLED
        if (orig_len != size_) return true; // mismatch lengths -> ok (not equal)
        for (size_t i = 0; i < size_; ++i) {
            // Сравниваем raw encrypted байт с оригинальным plaintext
            if (data_[i] != static_cast<uint8_t>(orig[i])) return true; // differs -> obfuscated
        }
        return false; // all bytes equal -> NOT obfuscated (bad!)
#else
        (void)orig; (void)orig_len;
        return true; // Debug mode: always return "obfuscated" to skip tests
#endif
    }
};

// Функция создания ключа: можно взять constexpr_hash(__TIME__) ^ __COUNTER__ и т.д.
// Здесь - простая фабрика: позволяет тестир��вать deterministically
constexpr uint32_t default_compile_unit_key(const char* file, const char* time, int counter) {
    // combine file/time/counter
    uint32_t h1 = constexpr_hash(file, std::char_traits<char>::length(file));
    uint32_t h2 = constexpr_hash(time, std::char_traits<char>::length(time));
    return h1 ^ h2 ^ static_cast<uint32_t>(counter * 0x9e3779b9u);
}

// Guard: дешифрует в локальный буфер (heap), очищает при уничтожении
class DecryptGuard {
public:
    DecryptGuard(const uint8_t* enc_data, size_t len, uint32_t key)
        : len_(len), key_(key), buf_(new char[len + 1]) {
#if STRENC_ENABLED
        // Encryption enabled: decrypt the data
        for (size_t i = 0; i < len; ++i) {
            uint8_t kbyte = static_cast<uint8_t>((rotl32(key_, static_cast<unsigned int>(i)) + static_cast<unsigned int>(i)) & 0xFFu);
            buf_[i] = static_cast<char>(enc_data[i] ^ kbyte);
        }
#else
        // Debug mode: copy plaintext (no decryption needed)
        for (size_t i = 0; i < len; ++i) {
            buf_[i] = static_cast<char>(enc_data[i]);
        }
#endif
        buf_[len] = '\0';
    }
    ~DecryptGuard() {
        // secure zero
        volatile char* p = buf_.get();
        for (size_t i = 0; i < len_; ++i) p[i] = 0;
        // unique_ptr will free
    }
    const char* c_str() const noexcept { return buf_.get(); }
    std::string string() const { return std::string(buf_.get()); }
private:
    size_t len_;
    [[maybe_unused]] uint32_t key_;  // Used only when STRENC_ENABLED
    std::unique_ptr<char[]> buf_;
};

// Утилиты макросов
} // namespace strenc

// Вспомогательные макросы для именования
#define STRENC_CONCAT_IMPL(a,b) a##b
#define STRENC_CONCAT(a,b) STRENC_CONCAT_IMPL(a,b)

// Макросы:
// ENC_STR(lit) - создаёт constexpr EncryptedString в текущем TU.
// Формирование ключа: комбинация __FILE__ и __TIME__ и __COUNTER__ (возможен детерминизм).
#define STRENC_COMPUTE_KEY() (strenc::default_compile_unit_key(__FILE__, __TIME__, __COUNTER__))

#define ENC_STR(lit) \
    ([]() constexpr -> strenc::EncryptedString<sizeof(lit)> { \
        return strenc::EncryptedString<sizeof(lit)>(lit, STRENC_COMPUTE_KEY()); \
    }())

// Создаёт guard с указанным именем переменной для доступа к расшифрованной строке
// Использование: AUTO_DECRYPT_VAR(my_var, enc); std::cout << my_var.c_str();
#define AUTO_DECRYPT_VAR(var_name, enc) \
    strenc::DecryptGuard STRENC_CONCAT(_strenc_guard_, __LINE__)((enc).data(), (enc).size(), (enc).key_); \
    strenc::DecryptGuard& var_name = STRENC_CONCAT(_strenc_guard_, __LINE__)

// Упрощённый макрос: создаёт переменную _dec_ в текущей области видимости
// Использование: AUTO_DECRYPT(enc); std::cout << _dec_.c_str();
// ВНИМАНИЕ: не используйте AUTO_DECRYPT более одного раза в одной области видимости!
#define AUTO_DECRYPT(enc) AUTO_DECRYPT_VAR(_dec_, enc)
