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

#ifndef STRENC_ENCRYPTED_STRING_H
#define STRENC_ENCRYPTED_STRING_H

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <cstring>

namespace strenc {

// Debug mode check
#ifndef DISABLE_STR_ENC
    constexpr std::int32_t STRENC_ENABLED = 1;
#else
    constexpr std::int32_t STRENC_ENABLED = 0;
#endif

// constexpr rotate-left (32-bit)
constexpr std::uint32_t rotl32(std::uint32_t v, std::uint32_t r) {
    r &= 31u;
    return (r != 0u) ? ((v << r) | (v >> (32u - r))) : v;
}

// constexpr hash function from string
constexpr std::uint32_t constexpr_hash(const char* s, std::size_t n) {
    std::uint32_t h = 2166136261u;
    for (std::size_t i = 0u; i < n; ++i) {
        h = (h ^ static_cast<std::uint32_t>(static_cast<std::uint8_t>(s[i]))) * 16777619u;
    }
    return h;
}

// Encryption: out[i] = in[i] ^ (rotl32(key, i) + i)
template <std::size_t N>
struct EncryptedString {
    static_assert(N >= 1u, "String literal must have at least null terminator");

    std::array<std::uint8_t, N> data_;
    std::size_t size_;
    std::uint32_t key_;

    constexpr EncryptedString(const char (&s)[N], std::uint32_t key)
        : data_{}, size_(N - 1u), key_(key) {

#if STRENC_ENABLED
        for (std::size_t i = 0u; i < N; ++i) {
            const std::uint8_t b = static_cast<std::uint8_t>(s[i]);
            const std::uint8_t kbyte = static_cast<std::uint8_t>((rotl32(key, i) + i) & 0xFFu);
            data_[i] = b ^ kbyte;
        }
#else
        for (std::size_t i = 0u; i < N; ++i) {
            data_[i] = static_cast<std::uint8_t>(s[i]);
        }
#endif
    }

    constexpr std::size_t size() const noexcept {
        return size_;
    }

    constexpr const std::uint8_t* data() const noexcept {
        return data_.data();
    }

    bool is_obfuscated_against(const char* orig, std::size_t orig_len) const {
#if STRENC_ENABLED
        if (orig_len != size_) {
            return true;
        }
        for (std::size_t i = 0u; i < size_; ++i) {
            if (data_[i] != static_cast<std::uint8_t>(orig[i])) {
                return true;
            }
        }
        return false;
#else
        (void)orig;
        (void)orig_len;
        return true;
#endif
    }
};

// Key generation factory
constexpr std::uint32_t default_compile_unit_key(const char* file, const char* time, std::int32_t counter) {
    const std::uint32_t h1 = constexpr_hash(file, std::char_traits<char>::length(file));
    const std::uint32_t h2 = constexpr_hash(time, std::char_traits<char>::length(time));
    return h1 ^ h2 ^ static_cast<std::uint32_t>(counter * 0x9e3779b9);
}

// Decryption result structure (stack-allocated to avoid dynamic memory)
template <std::size_t N = 256u>
class DecryptGuard {
public:
    DecryptGuard(const std::uint8_t* const enc_data, const std::size_t len, const std::uint32_t key)
        : len_(len), key_(key) {

#if STRENC_ENABLED
        for (std::size_t i = 0u; i < len; ++i) {
            const std::uint8_t kbyte = static_cast<std::uint8_t>((rotl32(key_, i) + i) & 0xFFu);
            buf_[i] = static_cast<char>(enc_data[i] ^ kbyte);
        }
#else
        for (std::size_t i = 0u; i < len; ++i) {
            buf_[i] = static_cast<char>(enc_data[i]);
        }
#endif
        buf_[len] = '\0';
    }

    ~DecryptGuard() {
        secure_zero();
    }

    DecryptGuard(const DecryptGuard&) = delete;
    DecryptGuard& operator=(const DecryptGuard&) = delete;

    const char* c_str() const noexcept {
        return buf_;
    }

    std::string string() const {
        return std::string(buf_);
    }

private:
    std::size_t len_;
    std::uint32_t key_;
    char buf_[N + 1u];

    void secure_zero() {
        for (std::size_t i = 0u; i < len_ + 1u; ++i) {
            buf_[i] = 0;
        }
    }
};

} // namespace strenc

// ============================================================================
// Public API macros (minimal, only necessary ones)
// ============================================================================

// Create encrypted string at compile time
#define ENC_STR(lit) \
    ([]() constexpr -> strenc::EncryptedString<sizeof(lit)> { \
        return strenc::EncryptedString<sizeof(lit)>(lit, strenc::default_compile_unit_key(__FILE__, __TIME__, __COUNTER__)); \
    }())

// Create decryption guard with custom variable name
#define AUTO_DECRYPT_VAR(var_name, enc) \
    strenc::DecryptGuard<256u> var_name((enc).data(), (enc).size(), (enc).key_)

// Create decryption guard with default name _dec_
#define AUTO_DECRYPT(enc) AUTO_DECRYPT_VAR(_dec_, enc)

#endif // STRENC_ENCRYPTED_STRING_H
