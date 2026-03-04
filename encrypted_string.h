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

// FNV-1a prime and offset basis
constexpr std::uint32_t FNV_OFFSET_BASIS = 2166136261U;
constexpr std::uint32_t FNV_PRIME = 16777619U;

// constexpr rotate-left (32-bit)
constexpr std::uint32_t rotl32(const std::uint32_t v, const std::uint32_t r) noexcept {
    const std::uint32_t masked_r = r & 31U;
    return (masked_r != 0U) ? ((v << masked_r) | (v >> (32U - masked_r))) : v;
}

// constexpr hash function from string
constexpr std::uint32_t constexpr_hash(const char* const s, const std::size_t n) noexcept {
    std::uint32_t hash_value = FNV_OFFSET_BASIS;
    for (std::size_t idx = 0U; idx < n; ++idx) {
        const std::uint32_t char_val = static_cast<std::uint32_t>(static_cast<unsigned char>(s[idx]));
        hash_value = (hash_value ^ char_val) * FNV_PRIME;
    }
    return hash_value;
}

// Encryption: out[i] = in[i] ^ (rotl32(key, i) + i)
template <std::size_t N>
struct EncryptedString {
    static_assert(N >= 1U, "String literal must have at least null terminator");

    std::array<std::uint8_t, N> data_;
    std::size_t size_;
    std::uint32_t key_;

    constexpr explicit EncryptedString(const char (&s)[N], const std::uint32_t key)
        : data_{}, size_(N - 1U), key_(key) {

#if STRENC_ENABLED
        for (std::size_t idx = 0U; idx < N; ++idx) {
            const std::uint8_t byte_val = static_cast<std::uint8_t>(s[idx]);
            const std::uint32_t rotl_val = rotl32(key, idx);
            const std::uint32_t temp = rotl_val + idx;
            const std::uint8_t kbyte = static_cast<std::uint8_t>(temp & 0xFFU);
            data_[idx] = byte_val ^ kbyte;
        }
#else
        for (std::size_t idx = 0U; idx < N; ++idx) {
            data_[idx] = static_cast<std::uint8_t>(s[idx]);
        }
#endif
    }

    constexpr std::size_t size() const noexcept {
        return size_;
    }

    constexpr const std::uint8_t* data() const noexcept {
        return data_.data();
    }

    bool is_obfuscated_against(const char* const orig, const std::size_t orig_len) const {
#if STRENC_ENABLED
        if (orig_len != size_) {
            return true;
        }
        for (std::size_t idx = 0U; idx < size_; ++idx) {
            if (data_[idx] != static_cast<std::uint8_t>(orig[idx])) {
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
constexpr std::uint32_t default_compile_unit_key(
    const char* const file,
    const char* const time_str,
    const std::int32_t counter) noexcept {

    const std::size_t file_len = static_cast<std::size_t>(std::char_traits<char>::length(file));
    const std::size_t time_len = static_cast<std::size_t>(std::char_traits<char>::length(time_str));
    const std::uint32_t h1 = constexpr_hash(file, file_len);
    const std::uint32_t h2 = constexpr_hash(time_str, time_len);

    const std::uint32_t counter_val = static_cast<std::uint32_t>(counter);
    const std::uint32_t mult_val = counter_val * 0x9E3779B9U;
    return (h1 ^ h2) ^ mult_val;
}

// Decryption result structure (stack-allocated to avoid dynamic memory)
template <std::size_t N = 256U>
class DecryptGuard {
public:
    explicit DecryptGuard(
        const std::uint8_t* const enc_data,
        const std::size_t len,
        const std::uint32_t key)
        : len_(len), key_(key) {

#if STRENC_ENABLED
        for (std::size_t idx = 0U; idx < len; ++idx) {
            const std::uint32_t rotl_val = rotl32(key_, idx);
            const std::uint32_t temp = rotl_val + idx;
            const std::uint8_t kbyte = static_cast<std::uint8_t>(temp & 0xFFU);
            const std::uint8_t xor_val = enc_data[idx] ^ kbyte;
            buf_[idx] = static_cast<char>(xor_val);
        }
#else
        for (std::size_t idx = 0U; idx < len; ++idx) {
            buf_[idx] = static_cast<char>(enc_data[idx]);
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
    const std::size_t len_;
    [[maybe_unused]] const std::uint32_t key_;
    char buf_[N + 1U];

    void secure_zero() noexcept {
        for (std::size_t idx = 0U; idx < (len_ + 1U); ++idx) {
            buf_[idx] = 0;
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
    strenc::DecryptGuard<256U> var_name((enc).data(), (enc).size(), (enc).key_)

// Create decryption guard with default name _dec_
#define AUTO_DECRYPT(enc) AUTO_DECRYPT_VAR(_dec_, enc)

#endif // STRENC_ENCRYPTED_STRING_H
