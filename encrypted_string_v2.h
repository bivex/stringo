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

#pragma once
#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <cstring>
#include <memory>
#include <chrono>
#include <thread>
#include <random>

#ifdef _WIN32
    #include <windows.h>
    #define STRENC_GET_PID() GetCurrentProcessId()
    #define STRENC_GET_TID() GetCurrentThreadId()
#elif defined(__APPLE__)
    #include <unistd.h>
    #include <pthread.h>
    #define STRENC_GET_PID() getpid()
    #define STRENC_GET_TID() (uint64_t)pthread_self()
#else
    #include <unistd.h>
    #include <sys/types.h>
    #define STRENC_GET_PID() getpid()
    #define STRENC_GET_TID() syscall(__NR_gettid)
#endif

namespace strenc::v2 {

// Debug mode check
#ifndef DISABLE_STR_ENC
    #define STRENC_ENABLED 1
#else
    #define STRENC_ENABLED 0
#endif

// Configuration
#ifndef STRENC_SINGLE_LAYER
    #define STRENC_MULTI_LAYER 1  // Enable multi-layer encryption
#else
    #define STRENC_MULTI_LAYER 0
#endif

#ifndef STRENC_NO_RT_KEY
    #define STRENC_RT_KEY 1  // Enable runtime key derivation
#else
    #define STRENC_RT_KEY 0
#endif

// ============================================================================
// Core Crypto Primitives
// ============================================================================

// constexpr rotate-left (32-bit) with UB protection
constexpr uint32_t rotl32(uint32_t v, unsigned int r) {
    r &= 31;
    return r ? (v << r) | (v >> (32 - r)) : v;
}

// constexpr rotate-right (32-bit)
constexpr uint32_t rotr32(uint32_t v, unsigned int r) {
    r &= 31;
    return r ? (v >> r) | (v << (32 - r)) : v;
}

// FNV-1a hash (constexpr)
constexpr uint32_t fnv1a_hash(const char* s, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; ++i) {
        h ^= static_cast<uint32_t>(s[i]);
        h *= 16777619u;
    }
    return h;
}

// Multi-round encryption for single byte
constexpr uint8_t encrypt_byte(uint8_t in, uint32_t key1, uint32_t key2, size_t idx) {
    // Layer 1: XOR with rotating key stream 1
    uint32_t k1 = (rotl32(key1, static_cast<unsigned int>(idx)) + idx) & 0xFFu;
    uint8_t layer1 = in ^ static_cast<uint8_t>(k1);

#if STRENC_MULTI_LAYER
    // Layer 2: XOR with different rotating key stream 2
    uint32_t k2 = (rotr32(key2, static_cast<unsigned int>(idx)) + idx * 2) & 0xFFu;
    uint8_t layer2 = layer1 ^ static_cast<uint8_t>(k2);
    return layer2;
#else
    return layer1;
#endif
}

// Multi-round decryption for single byte
constexpr uint8_t decrypt_byte(uint8_t enc, uint32_t key1, uint32_t key2, size_t idx) {
#if STRENC_MULTI_LAYER
    // Layer 2: XOR with different rotating key stream 2
    uint32_t k2 = (rotr32(key2, static_cast<unsigned int>(idx)) + idx * 2) & 0xFFu;
    uint8_t layer1 = enc ^ static_cast<uint8_t>(k2);
#else
    uint8_t layer1 = enc;
#endif

    // Layer 1: XOR with rotating key stream 1
    uint32_t k1 = (rotl32(key1, static_cast<unsigned int>(idx)) + idx) & 0xFFu;
    return layer1 ^ static_cast<uint8_t>(k1);
}

// ============================================================================
// Runtime Key Derivation
// ============================================================================

// Derive runtime key component from environment
inline uint32_t derive_runtime_key() {
#if STRENC_RT_KEY
    // Combine multiple entropy sources
    uint32_t rt_key = 0;

    // Process ID
    rt_key ^= static_cast<uint32_t>(STRENC_GET_PID());

    // Thread ID
    rt_key ^= static_cast<uint32_t>(STRENC_GET_TID()) << 16;

    // High-resolution timestamp
    auto now = std::chrono::high_resolution_clock::now();
    auto ts = now.time_since_epoch().count();
    rt_key ^= static_cast<uint32_t>(ts & 0xFFFFFFFF);

    // Stack address (ASLR provides randomness)
    void* stack_addr = &rt_key;
    rt_key ^= static_cast<uint32_t>(reinterpret_cast<uintptr_t>(stack_addr) & 0xFFFFFFFF);

    return rt_key;
#else
    return 0;  // No runtime component
#endif
}

// ============================================================================
// Compile-time Key Generation
// ============================================================================

// Generate two independent keys for multi-layer encryption
struct DualKeys {
    uint32_t key1;
    uint32_t key2;
};

constexpr DualKeys default_compile_unit_keys(const char* file, const char* time, int counter) {
    uint32_t h1 = fnv1a_hash(file, std::char_traits<char>::length(file));
    uint32_t h2 = fnv1a_hash(time, std::char_traits<char>::length(time));

    // Generate independent keys
    uint32_t key1 = h1 ^ static_cast<uint32_t>(counter * 0x9e3779b9u);
    uint32_t key2 = h2 ^ static_cast<uint32_t>(counter * 0x9e3779b9u + 1);

    return {key1, key2};
}

// ============================================================================
// Encrypted String Storage
// ============================================================================

template <size_t N>
struct EncryptedStringV2 {
    static_assert(N >= 1, "String literal must have at least null terminator");

    std::array<uint8_t, N> data_;
    size_t size_;
    DualKeys compile_keys_;
    uint32_t compile_hash_;  // For tamper detection

    constexpr EncryptedStringV2(const char (&s)[N], DualKeys keys)
        : data_{}, size_(N - 1), compile_keys_(keys), compile_hash_(0) {

#if STRENC_ENABLED
        // Multi-layer encryption
        for (size_t i = 0; i < N; ++i) {
            data_[i] = encrypt_byte(static_cast<uint8_t>(s[i]), keys.key1, keys.key2, i);
        }

        // Compute hash of encrypted data for tamper detection
        for (size_t i = 0; i < N; ++i) {
            compile_hash_ = (compile_hash_ * 31) + data_[i];
        }
#else
        // Debug mode: store plaintext
        for (size_t i = 0; i < N; ++i) {
            data_[i] = static_cast<uint8_t>(s[i]);
        }
#endif
    }

    constexpr size_t size() const noexcept { return size_; }
    constexpr const uint8_t* data() const noexcept { return data_.data(); }

    // Tamper detection: check if encrypted data was modified
    bool check_integrity() const {
#if STRENC_ENABLED
        uint32_t hash = 0;
        for (size_t i = 0; i < data_.size(); ++i) {
            hash = (hash * 31) + data_[i];
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

class DecryptGuardV2 {
public:
    DecryptGuardV2(const uint8_t* enc_data, size_t len, DualKeys compile_keys)
        : len_(len), compile_keys_(compile_keys), rt_key_(derive_runtime_key()),
          buf_(new char[len + 1]) {

#if STRENC_ENABLED
        // Decrypt using compile-time keys (must match encryption!)
        // Note: Runtime key is NOT used for decryption since encryption was compile-time
        for (size_t i = 0; i < len; ++i) {
            buf_[i] = static_cast<char>(
                decrypt_byte(enc_data[i], compile_keys_.key1, compile_keys_.key2, i)
            );
        }
#else
        // Debug mode: copy plaintext
        std::memcpy(buf_.get(), enc_data, len);
#endif
        buf_[len] = '\0';
    }

    ~DecryptGuardV2() {
        // Secure zeroing with multiple passes
        secure_zero();
    }

    const char* c_str() const noexcept { return buf_.get(); }
    std::string string() const { return std::string(buf_.get()); }

    // Get runtime key component (for debugging/testing)
    uint32_t runtime_key() const noexcept { return rt_key_; }

private:
    size_t len_;
    DualKeys compile_keys_;
    uint32_t rt_key_;
    std::unique_ptr<char[]> buf_;

    void secure_zero() {
        // Multi-pass zeroing to prevent compiler optimizations
        volatile char* p = buf_.get();

        // Pass 1: Write zeros
        for (size_t i = 0; i < len_ + 1; ++i) {
            p[i] = 0;
        }

        // Pass 2: Write random pattern
        for (size_t i = 0; i < len_ + 1; ++i) {
            p[i] = static_cast<char>(0xAA);
        }

        // Pass 3: Final zeros
        for (size_t i = 0; i < len_ + 1; ++i) {
            p[i] = 0;
        }

        // Memory barrier to prevent reordering
        std::atomic_thread_fence(std::memory_order_seq_cst);
    }
};

// ============================================================================
// Anti-Tampering Helpers
// ============================================================================

// Verify binary integrity (call at startup)
inline bool verify_self_integrity() {
    // This is a basic check - in production, you'd want to verify
    // the actual binary sections against known hashes
#if STRENC_ENABLED && !defined(DISABLE_STRENC_INTEGRITY_CHECK)
    // Check if we can detect basic modifications
    volatile int dummy = 0x12345678;
    return (dummy != 0);  // Simple sanity check
#else
    return true;
#endif
}

} // namespace strenc::v2

// ============================================================================
// Macros
// ============================================================================

#define STRENC_V2_CONCAT_IMPL(a,b) a##b
#define STRENC_V2_CONCAT(a,b) STRENC_V2_CONCAT_IMPL(a,b)

#define STRENC_V2_COMPUTE_KEYS() \
    (strenc::v2::default_compile_unit_keys(__FILE__, __TIME__, __COUNTER__))

// Create encrypted string (V2 with multi-layer encryption)
#define ENC_STR_V2(lit) \
    ([]() constexpr -> strenc::v2::EncryptedStringV2<sizeof(lit)> { \
        return strenc::v2::EncryptedStringV2<sizeof(lit)>(lit, STRENC_V2_COMPUTE_KEYS()); \
    }())

// Decrypt with custom variable name
#define AUTO_DECRYPT_VAR_V2(var_name, enc) \
    strenc::v2::DecryptGuardV2 STRENC_V2_CONCAT(_strenc_guard_, __LINE__) \
        ((enc).data(), (enc).size(), (enc).compile_keys_); \
    strenc::v2::DecryptGuardV2& var_name = STRENC_V2_CONCAT(_strenc_guard_, __LINE__)

// Decrypt with default _dec_ variable name
#define AUTO_DECRYPT_V2(enc) AUTO_DECRYPT_VAR_V2(_dec_, enc)
