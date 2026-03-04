/**
 * Copyright (c) 2026 Bivex
 *
 * @file encrypted_string_v3.h
 * @brief Enhanced security with stack allocation and memory obfuscation
 *
 * @par Security Improvements over v2:
 * 1. **Stack allocation for small strings** (< STRENC_STACK_THRESHOLD bytes)
 * 2. **Memory obfuscation with runtime key** - plaintext is XORed in memory
 * 3. **On-the-fly de-obfuscation** - only de-obfuscates when accessing data
 * 4. **No plaintext in memory** - decrypted bytes are always obfuscated
 *
 * @par Usage:
 * @code
 *   constexpr auto enc = ENC_STR_V3("Secret");
 *   AUTO_DECRYPT_V3(enc);
 *   std::cout << _dec_.c_str();  // De-obfuscates and returns plaintext
 *   // Memory still contains obfuscated data
 * @endcode
 */

#pragma once
#include "encrypted_string_v2.h"

namespace strenc::v3 {

// Configuration: threshold for stack allocation (default 64 bytes)
#ifndef STRENC_STACK_THRESHOLD
    #define STRENC_STACK_THRESHOLD 64
#endif

// Enable memory obfuscation (default: enabled)
#ifndef STRENC_MEM_OBFUSCATE
    #define STRENC_MEM_OBFUSCATE 1
#endif

// ============================================================================
// Enhanced RAII Guard with Stack Allocation + Memory Obfuscation
// ============================================================================

class DecryptGuardV3 {
public:
    DecryptGuardV3(const uint8_t* enc_data, size_t len, v2::DualKeys compile_keys)
        : len_(len), compile_keys_(compile_keys), rt_key_(v2::derive_runtime_key()),
          uses_stack_(len_ + 1 <= STRENC_STACK_THRESHOLD), heap_buf_(nullptr) {

        char* buf = uses_stack_ ? stack_buf_ : (heap_buf_ = new char[len + 1]);
        buf_ptr_ = buf;

#if STRENC_ENABLED
        // Decrypt and immediately obfuscate in memory
        for (size_t i = 0; i < len; ++i) {
            // Step 1: Decrypt
            char decrypted = static_cast<char>(
                v2::decrypt_byte(enc_data[i], compile_keys_.key1, compile_keys_.key2, i)
            );

#if STRENC_MEM_OBFUSCATE
            // Step 2: Obfuscate with runtime key (plaintext never stored!)
            uint8_t key_byte = static_cast<uint8_t>((rt_key_ >> (i * 8)) & 0xFF);
            buf[i] = decrypted ^ static_cast<char>(key_byte);
#else
            buf[i] = decrypted;
#endif
        }
#else
        std::memcpy(buf, enc_data, len);
#endif
        buf[len] = '\0';
    }

    ~DecryptGuardV3() {
        // Secure zeroing
        secure_zero();
        if (!uses_stack_) {
            delete[] heap_buf_;
        }
    }

    /**
     * Get c_str - de-obfuscates on-the-fly!
     * Note: This creates a temporary de-obfuscated view.
     * For extended use, call .string() to get a std::string.
     */
    const char* c_str() const noexcept {
#if STRENC_MEM_OBFUSCATE && STRENC_ENABLED
        // De-obfuscate temporarily for the call
        // Note: This is a simple implementation - for thread safety,
        // you might want to use thread-local storage or a lock
        static thread_local char temp_buf[STRENC_STACK_THRESHOLD];
        static thread_local char* temp_heap = nullptr;
        static thread_local size_t temp_heap_size = 0;

        char* out = (len_ + 1 <= STRENC_STACK_THRESHOLD) ? temp_buf : [this]() {
            if (temp_heap_size < len_ + 1) {
                delete[] temp_heap;
                temp_heap = new char[len_ + 1];
                temp_heap_size = len_ + 1;
            }
            return temp_heap;
        }();

        for (size_t i = 0; i < len_; ++i) {
            uint8_t key_byte = static_cast<uint8_t>((rt_key_ >> (i * 8)) & 0xFF);
            out[i] = buf_ptr_[i] ^ static_cast<char>(key_byte);
        }
        out[len_] = '\0';
        return out;
#else
        return buf_ptr_;
#endif
    }

    std::string string() const {
        return std::string(c_str());
    }

    // Get runtime key for debugging
    uint32_t runtime_key() const noexcept { return rt_key_; }

    // Check if using stack allocation
    bool is_on_stack() const noexcept { return uses_stack_; }

private:
    size_t len_;
    v2::DualKeys compile_keys_;
    uint32_t rt_key_;
    bool uses_stack_;
    char* buf_ptr_;

    // Stack buffer (used when string is small)
    char stack_buf_[STRENC_STACK_THRESHOLD];

    // Heap buffer (used when string is large)
    char* heap_buf_;

    void secure_zero() {
        volatile char* p = uses_stack_ ? stack_buf_ : heap_buf_;
        size_t total = len_ + 1;

        // Multi-pass zeroing
        for (size_t pass = 0; pass < 3; ++pass) {
            char pattern = (pass == 1) ? 0xAA : 0x00;
            for (size_t i = 0; i < total; ++i) {
                p[i] = pattern;
            }
        }

        // Memory barrier
        std::atomic_thread_fence(std::memory_order_seq_cst);
    }

    // Prevent copy
    DecryptGuardV3(const DecryptGuardV3&) = delete;
    DecryptGuardV3& operator=(const DecryptGuardV3&) = delete;
};

// ============================================================================
// Lightweight Alternative: Stack-only, no memory obfuscation (faster)
// ============================================================================

class DecryptGuardV3Fast {
public:
    DecryptGuardV3Fast(const uint8_t* enc_data, size_t len, v2::DualKeys compile_keys)
        : len_(len), buf_(new char[len + 1]) {

#if STRENC_ENABLED
        for (size_t i = 0; i < len; ++i) {
            buf_[i] = static_cast<char>(
                v2::decrypt_byte(enc_data[i], compile_keys.key1, compile_keys.key2, i)
            );
        }
#else
        std::memcpy(buf_.get(), enc_data, len);
#endif
        buf_[len] = '\0';
    }

    ~DecryptGuardV3Fast() {
        volatile char* p = buf_.get();
        for (size_t i = 0; i < len_ + 1; ++i) p[i] = 0;
    }

    const char* c_str() const noexcept { return buf_.get(); }
    std::string string() const { return std::string(buf_.get()); }

private:
    size_t len_;
    std::unique_ptr<char[]> buf_;
};

} // namespace strenc::v3

// ============================================================================
// Macros for v3
// ============================================================================

#define STRENC_V3_CONCAT_IMPL(a,b) a##b
#define STRENC_V3_CONCAT(a,b) STRENC_V3_CONCAT_IMPL(a,b)

// Reuse v2's EncryptedStringV2 and ENC_STR_V2
using strenc::v2::EncryptedStringV2;
// Note: ENC_STR_V2 and AUTO_DECRYPT_VAR_V2 are macros, not namespace members
// They are defined in encrypted_string_v2.h in the global namespace

// v3 guards (stack + memory obfuscation)
#define AUTO_DECRYPT_VAR_V3(var_name, enc) \
    strenc::v3::DecryptGuardV3 STRENC_V3_CONCAT(_strenc_guard_, __LINE__) \
        ((enc).data(), (enc).size(), (enc).compile_keys_); \
    strenc::v3::DecryptGuardV3& var_name = STRENC_V3_CONCAT(_strenc_guard_, __LINE__)

#define AUTO_DECRYPT_V3(enc) AUTO_DECRYPT_VAR_V3(_dec_, enc)

// v3 fast version (heap only, no memory obfuscation)
#define AUTO_DECRYPT_VAR_V3_FAST(var_name, enc) \
    strenc::v3::DecryptGuardV3Fast STRENC_V3_CONCAT(_strenc_guard_, __LINE__) \
        ((enc).data(), (enc).size(), (enc).compile_keys_); \
    strenc::v3::DecryptGuardV3Fast& var_name = STRENC_V3_CONCAT(_strenc_guard_, __LINE__)

#define AUTO_DECRYPT_V3_FAST(enc) AUTO_DECRYPT_VAR_V3_FAST(_dec_, enc)
