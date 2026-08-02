/**
 * Copyright (c) 2026 Bivex
 *
 * @file encrypted_string_v6.h
 * @brief Enterprise Kernel-Grade Polymorphic String Encryption (v6)
 */

#ifndef STRENC_ENCRYPTED_STRING_V6_H
#define STRENC_ENCRYPTED_STRING_V6_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <type_traits>

#if defined(_WIN32) || defined(_WIN64) || defined(_KERNEL_MODE)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#else
typedef struct _UNICODE_STRING {
    std::uint16_t Length;
    std::uint16_t MaximumLength;
    wchar_t*      Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _STRING {
    std::uint16_t Length;
    std::uint16_t MaximumLength;
    char*         Buffer;
} STRING, *PSTRING, ANSI_STRING, *PANSI_STRING;
#endif

#if defined(_M_ARM64) || defined(__aarch64__)
#include <arm_neon.h>
#define STRENC_HAS_NEON 1
#elif defined(__AVX2__) || defined(_MSC_VER)
#include <immintrin.h>
#define STRENC_HAS_AVX2 1
#endif

namespace strenc {
namespace v6 {

/**
 * @class SecureKernelString
 * @brief Stack-allocated string buffer with native UNICODE_STRING & ANSI_STRING exports
 */
template <typename CharT, std::size_t N>
class SecureKernelString {
private:
    alignas(16) CharT m_buffer[N];
    bool m_active;

public:
    constexpr SecureKernelString() noexcept : m_buffer{0}, m_active(true) {}

    // RVO Move Constructor
    SecureKernelString(SecureKernelString&& other) noexcept : m_active(true) {
        std::memcpy(m_buffer, other.m_buffer, N * sizeof(CharT));
        other.m_active = false;
    }

    CharT* data() noexcept { return m_buffer; }
    const CharT* c_str() const noexcept { return m_buffer; }
    constexpr std::size_t size() const noexcept { return N - 1; }

    UNICODE_STRING to_unicode_string() noexcept {
        UNICODE_STRING us;
        us.Length = static_cast<std::uint16_t>((N - 1) * sizeof(wchar_t));
        us.MaximumLength = static_cast<std::uint16_t>(N * sizeof(wchar_t));
        us.Buffer = reinterpret_cast<wchar_t*>(m_buffer);
        return us;
    }

    STRING to_ansi_string() noexcept {
        STRING as;
        as.Length = static_cast<std::uint16_t>(N - 1);
        as.MaximumLength = static_cast<std::uint16_t>(N);
        as.Buffer = reinterpret_cast<char*>(m_buffer);
        return as;
    }

    // Volatile Zero Memory Scrubbing upon destruction
    ~SecureKernelString() noexcept {
        if (m_active) {
            volatile CharT* p = m_buffer;
            for (std::size_t i = 0; i < N; ++i) {
                p[i] = 0;
            }
        }
    }

    SecureKernelString(const SecureKernelString&) = delete;
    SecureKernelString& operator=(const SecureKernelString&) = delete;
    SecureKernelString& operator=(SecureKernelString&&) = delete;
};

/**
 * @struct EncryptedStringV6
 * @brief Polymorphic compile-time encrypted string (supports char and wchar_t)
 */
template <typename CharT, std::size_t N>
struct EncryptedStringV6 {
    alignas(16) CharT encrypted[N];
    std::uint32_t key;

    constexpr EncryptedStringV6(const CharT (&s)[N], std::uint32_t k) : encrypted{}, key(k) {
        for (std::size_t i = 0; i < N; ++i) {
            std::uint32_t charVal = static_cast<std::uint32_t>(s[i]);
            std::uint32_t kMod = key + static_cast<std::uint32_t>(i * 0x9E3779B9U);
            encrypted[i] = static_cast<CharT>(charVal ^ (kMod & 0xFFFFU));
        }
    }

    /**
     * @brief Decrypts payload into stack-allocated SecureKernelString
     */
    SecureKernelString<CharT, N> decrypt_stack() const noexcept {
        SecureKernelString<CharT, N> secureStr;
        CharT* dst = secureStr.data();

        std::size_t idx = 0;

#if defined(STRENC_HAS_NEON) && (defined(__aarch64__) || defined(_M_ARM64))
        if (std::is_same<CharT, char>::value && N >= 16) {
            for (; idx + 16 <= N - 1; idx += 16) {
                uint8x16_t encVec = vld1q_u8(reinterpret_cast<const uint8_t*>(&encrypted[idx]));
                alignas(16) uint8_t keyArr[16];
                for (size_t k = 0; k < 16; ++k) {
                    std::uint32_t kMod = key + static_cast<std::uint32_t>((idx + k) * 0x9E3779B9U);
                    keyArr[k] = static_cast<uint8_t>(kMod & 0xFFU);
                }
                uint8x16_t keyVec = vld1q_u8(keyArr);
                uint8x16_t decVec = veorq_u8(encVec, keyVec);
                vst1q_u8(reinterpret_cast<uint8_t*>(&dst[idx]), decVec);
            }
        }
#endif

        // Scalar fallback loop
        for (; idx < N - 1; ++idx) {
            std::uint32_t encVal = static_cast<std::uint32_t>(encrypted[idx]);
            std::uint32_t kMod = key + static_cast<std::uint32_t>(idx * 0x9E3779B9U);
            dst[idx] = static_cast<CharT>(encVal ^ (kMod & 0xFFFFU));
        }
        dst[N - 1] = 0;
        return secureStr;
    }
};

// Macro for ASCII strings
#define ENC_STR_V6(lit) \
    ([]() -> strenc::v6::EncryptedStringV6<char, sizeof(lit)> { \
        return strenc::v6::EncryptedStringV6<char, sizeof(lit)>(lit, 0xABCDEF12U); \
    }())

// Macro for Wide UNICODE strings (wchar_t)
#define ENC_USTR_V6(lit) \
    ([]() -> strenc::v6::EncryptedStringV6<wchar_t, sizeof(lit)/sizeof(wchar_t)> { \
        return strenc::v6::EncryptedStringV6<wchar_t, sizeof(lit)/sizeof(wchar_t)>(lit, 0x1234ABCDU); \
    }())

} // namespace v6
} // namespace strenc

#endif // STRENC_ENCRYPTED_STRING_V6_H
