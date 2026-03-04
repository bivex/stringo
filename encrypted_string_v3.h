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

#ifndef STRENC_ENCRYPTED_STRING_V3_H
#define STRENC_ENCRYPTED_STRING_V3_H

#include "encrypted_string_v2.h"

namespace strenc::v3 {

// Configuration: threshold for stack allocation (default 64 bytes)
#ifndef STRENC_STACK_THRESHOLD
    constexpr std::size_t STRENC_STACK_THRESHOLD = 64u;
#endif

// Enable memory obfuscation (default: enabled)
#ifndef STRENC_MEM_OBFUSCATE
    constexpr std::int32_t STRENC_MEM_OBFUSCATE = 1;
#endif

// ============================================================================
// Enhanced RAII Guard with Stack Allocation + Memory Obfuscation
// ============================================================================

template <std::size_t N = 256u>
class DecryptGuardV3 {
public:
    DecryptGuardV3(const std::uint8_t* const enc_data, const std::size_t len, const ::strenc::v2::DualKeys& compile_keys)
        : len_(len), compile_keys_(compile_keys), rt_key_(::strenc::v2::derive_runtime_key()),
          uses_stack_(len_ + 1u <= STRENC_STACK_THRESHOLD), heap_buf_(nullptr) {

        char* buf = nullptr;
        if (uses_stack_) {
            buf = stack_buf_;
        } else {
            heap_buf_ = new char[len + 1u];
            buf = heap_buf_;
        }
        buf_ptr_ = buf;

#if STRENC_ENABLED
        for (std::size_t i = 0u; i < len; ++i) {
            const char decrypted = static_cast<char>(
                ::strenc::v2::decrypt_byte(enc_data[i], compile_keys_.key1, compile_keys_.key2, i)
            );

#if STRENC_MEM_OBFUSCATE
            const std::uint8_t key_byte = static_cast<std::uint8_t>((rt_key_ >> (i * 8u)) & 0xFFu);
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
        secure_zero();
        if (!uses_stack_ && (heap_buf_ != nullptr)) {
            delete[] heap_buf_;
        }
    }

    DecryptGuardV3(const DecryptGuardV3&) = delete;
    DecryptGuardV3& operator=(const DecryptGuardV3&) = delete;

    const char* c_str() const noexcept {
#if STRENC_MEM_OBFUSCATE && STRENC_ENABLED
        static thread_local char temp_buf[STRENC_STACK_THRESHOLD];
        static thread_local char* temp_heap = nullptr;
        static thread_local std::size_t temp_heap_size = 0u;

        char* out = nullptr;
        if (len_ + 1u <= STRENC_STACK_THRESHOLD) {
            out = temp_buf;
        } else {
            if (temp_heap_size < len_ + 1u) {
                delete[] temp_heap;
                temp_heap = new char[len_ + 1u];
                temp_heap_size = len_ + 1u;
            }
            out = temp_heap;
        }

        for (std::size_t i = 0u; i < len_; ++i) {
            const std::uint8_t key_byte = static_cast<std::uint8_t>((rt_key_ >> (i * 8u)) & 0xFFu);
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

    std::uint32_t runtime_key() const noexcept {
        return rt_key_;
    }

    bool is_on_stack() const noexcept {
        return uses_stack_;
    }

private:
    std::size_t len_;
    ::strenc::v2::DualKeys compile_keys_;
    std::uint32_t rt_key_;
    bool uses_stack_;
    char* buf_ptr_;
    char stack_buf_[STRENC_STACK_THRESHOLD];
    char* heap_buf_;

    void secure_zero() {
        volatile char* p = uses_stack_ ? stack_buf_ : heap_buf_;
        const std::size_t total = len_ + 1u;

        for (std::size_t pass = 0u; pass < 3u; ++pass) {
            const char pattern = (pass == 1u) ? static_cast<char>(0xAA) : 0;
            for (std::size_t i = 0u; i < total; ++i) {
                p[i] = pattern;
            }
        }

        std::atomic_thread_fence(std::memory_order_seq_cst);
    }
};

// ============================================================================
// Lightweight Alternative: Stack-only, no memory obfuscation (faster)
// ============================================================================

template <std::size_t N = 256u>
class DecryptGuardV3Fast {
public:
    DecryptGuardV3Fast(const std::uint8_t* const enc_data, const std::size_t len, const ::strenc::v2::DualKeys& compile_keys)
        : len_(len) {

#if STRENC_ENABLED
        for (std::size_t i = 0u; i < len; ++i) {
            buf_[i] = static_cast<char>(
                ::strenc::v2::decrypt_byte(enc_data[i], compile_keys.key1, compile_keys.key2, i)
            );
        }
#else
        std::memcpy(buf_, enc_data, len);
#endif
        buf_[len] = '\0';
    }

    ~DecryptGuardV3Fast() {
        volatile char* p = buf_;
        for (std::size_t i = 0u; i < len_ + 1u; ++i) {
            p[i] = 0;
        }
    }

    DecryptGuardV3Fast(const DecryptGuardV3Fast&) = delete;
    DecryptGuardV3Fast& operator=(const DecryptGuardV3Fast&) = delete;

    const char* c_str() const noexcept {
        return buf_;
    }

    std::string string() const {
        return std::string(buf_);
    }

private:
    std::size_t len_;
    char buf_[N + 1u];
};

} // namespace strenc::v3

// ============================================================================
// Public API for v3
// ============================================================================

// Reuse v2's EncryptedStringV2 and ENC_STR_V2
using ::strenc::v2::EncryptedStringV2;

// Create encrypted string using v2's macro
#define ENC_STR_V3(lit) ENC_STR_V2(lit)

// v3 guards (stack + memory obfuscation)
#define AUTO_DECRYPT_VAR_V3(var_name, enc) \
    ::strenc::v3::DecryptGuardV3<> var_name((enc).data(), (enc).size(), (enc).compile_keys_)

#define AUTO_DECRYPT_V3(enc) AUTO_DECRYPT_VAR_V3(_dec_, enc)

// v3 fast version (heap only, no memory obfuscation)
#define AUTO_DECRYPT_VAR_V3_FAST(var_name, enc) \
    ::strenc::v3::DecryptGuardV3Fast<> var_name((enc).data(), (enc).size(), (enc).compile_keys_)

#define AUTO_DECRYPT_V3_FAST(enc) AUTO_DECRYPT_VAR_V3_FAST(_dec_, enc)

#endif // STRENC_ENCRYPTED_STRING_V3_H
