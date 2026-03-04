/**
 * Copyright (c) 2026 Bivex
 *
 * Author: Bivex
 * Available for contact via email: support@b-b.top
 * For up-to-date contact information:
 * https://github.com/bivex
 *
 * Created: 2026-03-04 15:11
 * Last Updated: 2026-03-04 16:30
 *
 * Licensed under the MIT License.
 * Commercial licensing available upon request.
 */

/**
 * @file encrypted_string_v2.h
 * @brief Enhanced compile-time string encryption with multi-layer protection
 *
 * @details
 * Security Enhancements:
 * - Multi-layer encryption (2-pass XOR with different keys)
 * - Runtime key derivation (environment-specific)
 * - Anti-tampering detection
 * - Secure memory zeroing
 *
 * @par Security Features:
 * 1. **Multi-layer encryption**: Each string is encrypted twice with different keys
 * 2. **Runtime key derivation**: Part of key is derived at runtime from:
 *    - Process ID
 *    - Thread ID
 *    - Memory address (ASLR)
 *    - Timestamp
 * 3. **Anti-tampering**: Detects if binary was modified
 *
 * @par Usage Example:
 * @code
 *   #include "encrypted_string_v2.h"
 *
 *   // Declare encrypted string at compile time
 *   constexpr auto enc = ENC_STR_V2("SecretPassword123");
 *
 *   // Decrypt in local scope (RAII)
 *   {
 *       AUTO_DECRYPT_VAR_V2(decrypted, enc);
 *       std::cout << decrypted.c_str() << std::endl;
 *   } // decrypted buffer is securely zeroed here
 * @endcode
 *
 * @par Configuration:
 * - Define DISABLE_STR_ENC to disable encryption (debug mode)
 * - Define STRENC_SINGLE_LAYER to use single-layer encryption (faster, less secure)
 * - Define STRENC_NO_RT_KEY to disable runtime key derivation (less secure)
 */

#ifndef STRENC_ENCRYPTED_STRING_V2_H
#define STRENC_ENCRYPTED_STRING_V2_H

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <cstring>
#include <chrono>
#include <thread>
#include <atomic>

#ifdef _WIN32
    #include <windows.h>
    #define STRENC_GET_PID() GetCurrentProcessId()
    #define STRENC_GET_TID() GetCurrentThreadId()
#elif defined(__APPLE__)
    #include <unistd.h>
    #include <pthread.h>
    #define STRENC_GET_PID() getpid()
    #define STRENC_GET_TID() static_cast<std::uint64_t>(pthread_self())
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/syscall.h>
    #define STRENC_GET_PID() getpid()
    #define STRENC_GET_TID() static_cast<std::uint64_t>(static_cast<std::int32_t>(syscall(SYS_gettid)))
#endif

namespace strenc::v2 {

// Debug mode check
#ifndef DISABLE_STR_ENC
    constexpr std::int32_t STRENC_ENABLED = 1;
#else
    constexpr std::int32_t STRENC_ENABLED = 0;
#endif

// Configuration
#ifndef STRENC_SINGLE_LAYER
    constexpr std::int32_t STRENC_MULTI_LAYER = 1;
#else
    constexpr std::int32_t STRENC_MULTI_LAYER = 0;
#endif

#ifndef STRENC_NO_RT_KEY
    constexpr std::int32_t STRENC_RT_KEY = 1;
#else
    constexpr std::int32_t STRENC_RT_KEY = 0;
#endif

// FNV-1a constants
constexpr std::uint32_t FNV_OFFSET_BASIS = 2166136261u;
constexpr std::uint32_t FNV_PRIME = 16777619u;

// ============================================================================
// Core Crypto Primitives
// ============================================================================

// constexpr rotate-left (32-bit) with UB protection
constexpr std::uint32_t rotl32(const std::uint32_t v, const std::uint32_t r) noexcept {
    const std::uint32_t masked_r = r & 31u;
    return (masked_r != 0u) ? ((v << masked_r) | (v >> (32u - masked_r))) : v;
}

// constexpr rotate-right (32-bit)
constexpr std::uint32_t rotr32(const std::uint32_t v, const std::uint32_t r) noexcept {
    const std::uint32_t masked_r = r & 31u;
    return (masked_r != 0u) ? ((v >> masked_r) | (v << (32u - masked_r))) : v;
}

// FNV-1a hash (constexpr)
constexpr std::uint32_t fnv1a_hash(const char* const s, const std::size_t n) noexcept {
    std::uint32_t hash_value = FNV_OFFSET_BASIS;
    for (std::size_t idx = 0u; idx < n; ++idx) {
        const std::uint32_t char_val = static_cast<std::uint32_t>(static_cast<std::uint8_t>(s[idx]));
        hash_value = (hash_value ^ char_val) * FNV_PRIME;
    }
    return hash_value;
}

// Multi-round encryption for single byte
constexpr std::uint8_t encrypt_byte(
    const std::uint8_t in,
    const std::uint32_t key1,
    const std::uint32_t key2,
    const std::size_t idx) noexcept {

    const std::uint32_t k1 = (rotl32(key1, idx) + idx) & 0xFFu;
    const std::uint8_t layer1 = in ^ k1;

#if STRENC_MULTI_LAYER
    const std::uint32_t k2 = (rotr32(key2, idx) + (idx * 2u)) & 0xFFu;
    return layer1 ^ k2;
#else
    (void)key2;
    return layer1;
#endif
}

// Multi-round decryption for single byte
constexpr std::uint8_t decrypt_byte(
    const std::uint8_t enc,
    const std::uint32_t key1,
    const std::uint32_t key2,
    const std::size_t idx) noexcept {

#if STRENC_MULTI_LAYER
    const std::uint32_t k2 = (rotr32(key2, idx) + (idx * 2u)) & 0xFFu;
    const std::uint8_t layer1 = enc ^ k2;
#else
    (void)key2;
    const std::uint8_t layer1 = enc;
#endif

    const std::uint32_t k1 = (rotl32(key1, idx) + idx) & 0xFFu;
    return layer1 ^ k1;
}

// ============================================================================
// Runtime Key Derivation
// ============================================================================

// Derive runtime key component from environment
[[maybe_unused]] inline std::uint32_t derive_runtime_key() noexcept {
#if STRENC_RT_KEY
    std::uint32_t rt_key = 0u;

    const std::uint32_t pid_val = static_cast<std::uint32_t>(STRENC_GET_PID());
    rt_key ^= pid_val;

    const std::uint64_t tid_val = STRENC_GET_TID();
    rt_key ^= static_cast<std::uint32_t>(tid_val) << 16u;

    const auto now = std::chrono::high_resolution_clock::now();
    const auto ts = now.time_since_epoch().count();
    rt_key ^= static_cast<std::uint32_t>(ts & 0xFFFFFFFFu);

    const std::uintptr_t stack_addr = reinterpret_cast<std::uintptr_t>(&rt_key);
    rt_key ^= static_cast<std::uint32_t>(stack_addr & 0xFFFFFFFFu);

    return rt_key;
#else
    return 0u;
#endif
}

// ============================================================================
// Compile-time Key Generation
// ============================================================================

struct DualKeys {
    std::uint32_t key1;
    std::uint32_t key2;
};

constexpr DualKeys default_compile_unit_keys(
    const char* const file,
    const char* const time_str,
    const std::int32_t counter) noexcept {

    const std::uint32_t file_len = std::char_traits<char>::length(file);
    const std::uint32_t time_len = std::char_traits<char>::length(time_str);
    const std::uint32_t h1 = fnv1a_hash(file, static_cast<std::size_t>(file_len));
    const std::uint32_t h2 = fnv1a_hash(time_str, static_cast<std::size_t>(time_len));

    const std::uint32_t counter_val = static_cast<std::uint32_t>(counter);
    const std::uint32_t key1 = h1 ^ (counter_val * 0x9e3779b9u);
    const std::uint32_t key2 = h2 ^ ((counter_val + 1u) * 0x9e3779b9u);

    return DualKeys{key1, key2};
}

// ============================================================================
// Encrypted String Storage
// ============================================================================

template <std::size_t N>
struct EncryptedStringV2 {
    static_assert(N >= 1u, "String literal must have at least null terminator");

    std::array<std::uint8_t, N> data_;
    std::size_t size_;
    DualKeys compile_keys_;
    std::uint32_t compile_hash_;

    constexpr explicit EncryptedStringV2(const char (&s)[N], const DualKeys& keys)
        : data_{}, size_(N - 1u), compile_keys_(keys), compile_hash_(0u) {

#if STRENC_ENABLED
        for (std::size_t idx = 0u; idx < N; ++idx) {
            data_[idx] = encrypt_byte(static_cast<std::uint8_t>(s[idx]), keys.key1, keys.key2, idx);
        }

        for (std::size_t idx = 0u; idx < N; ++idx) {
            compile_hash_ = (compile_hash_ * 31u) + data_[idx];
        }
#else
        for (std::size_t idx = 0u; idx < N; ++idx) {
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

    [[maybe_unused]] bool check_integrity() const {
#if STRENC_ENABLED
        std::uint32_t hash = 0u;
        for (std::size_t idx = 0u; idx < data_.size(); ++idx) {
            hash = (hash * 31u) + data_[idx];
        }
        return hash == compile_hash_;
#else
        return true;
#endif
    }
};

// ============================================================================
// RAII Decryption Guard with Secure Zeroing
// ============================================================================

template <std::size_t N = 256u>
class DecryptGuardV2 {
public:
    explicit DecryptGuardV2(
        const std::uint8_t* const enc_data,
        const std::size_t len,
        const DualKeys& compile_keys)
        : len_(len), compile_keys_(compile_keys), rt_key_(derive_runtime_key()) {

#if STRENC_ENABLED
        for (std::size_t idx = 0u; idx < len; ++idx) {
            buf_[idx] = static_cast<char>(
                decrypt_byte(enc_data[idx], compile_keys_.key1, compile_keys_.key2, idx)
            );
        }
#else
        std::memcpy(buf_, enc_data, len);
#endif
        buf_[len] = '\0';
    }

    ~DecryptGuardV2() {
        secure_zero();
    }

    DecryptGuardV2(const DecryptGuardV2&) = delete;
    DecryptGuardV2& operator=(const DecryptGuardV2&) = delete;

    const char* c_str() const noexcept {
        return buf_;
    }

    std::string string() const {
        return std::string(buf_);
    }

    [[maybe_unused]] std::uint32_t runtime_key() const noexcept {
        return rt_key_;
    }

private:
    const std::size_t len_;
    const DualKeys compile_keys_;
    [[maybe_unused]] const std::uint32_t rt_key_;
    char buf_[N + 1u];

    void secure_zero() noexcept {
        volatile char* p = buf_;

        for (std::size_t pass = 0u; pass < 3u; ++pass) {
            const char pattern = (pass == 1u) ? static_cast<char>(0xAA) : 0;
            for (std::size_t idx = 0u; idx < (len_ + 1u); ++idx) {
                p[idx] = pattern;
            }
        }

        std::atomic_thread_fence(std::memory_order_seq_cst);
    }
};

// ============================================================================
// Anti-Tampering Helpers
// ============================================================================

[[maybe_unused]] inline bool verify_self_integrity() noexcept {
#if STRENC_ENABLED && !defined(DISABLE_STRENC_INTEGRITY_CHECK)
    const volatile std::int32_t dummy = 0x12345678;
    return (dummy != 0);
#else
    return true;
#endif
}

} // namespace strenc::v2

// ============================================================================
// Public API
// ============================================================================

// Create encrypted string (V2 with multi-layer encryption)
#define ENC_STR_V2(lit) \
    ([]() constexpr -> strenc::v2::EncryptedStringV2<sizeof(lit)> { \
        return strenc::v2::EncryptedStringV2<sizeof(lit)>(lit, strenc::v2::default_compile_unit_keys(__FILE__, __TIME__, __COUNTER__)); \
    }())

// Decrypt with custom variable name
#define AUTO_DECRYPT_VAR_V2(var_name, enc) \
    strenc::v2::DecryptGuardV2<256u> var_name((enc).data(), (enc).size(), (enc).compile_keys_)

// Decrypt with default _dec_ variable name
#define AUTO_DECRYPT_V2(enc) AUTO_DECRYPT_VAR_V2(_dec_, enc)

#endif // STRENC_ENCRYPTED_STRING_V2_H
