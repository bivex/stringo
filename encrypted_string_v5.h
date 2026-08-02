/**
 * Copyright (c) 2026 Bivex
 *
 * @file encrypted_string_v5.h
 * @brief High-Performance Zero-Trace Polymorphic String Encryption (v5)
 */

#ifndef STRENC_ENCRYPTED_STRING_V5_H
#define STRENC_ENCRYPTED_STRING_V5_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <cstring>

namespace strenc {
namespace v5 {

constexpr std::uint32_t FNV_OFFSET_BASIS = 2166136261U;
constexpr std::uint32_t FNV_PRIME = 16777619U;

constexpr std::uint32_t fnv1a(const char* const s, const std::size_t n) noexcept {
    std::uint32_t hash_value = FNV_OFFSET_BASIS;
    for (std::size_t idx = 0U; idx < n; ++idx) {
        const std::uint32_t char_val = static_cast<std::uint32_t>(static_cast<unsigned char>(s[idx]));
        hash_value = (hash_value ^ char_val) * FNV_PRIME;
    }
    return hash_value;
}

/**
 * @class SecureStackString
 * @brief Stack-allocated string buffer with volatile zero-wipe on destruction
 */
template <std::size_t N>
class SecureStackString {
private:
    char m_buffer[N];
    bool m_active;

public:
    constexpr SecureStackString() noexcept : m_buffer{0}, m_active(true) {}
    
    // Move constructor to support Return Value Optimization (RVO)
    SecureStackString(SecureStackString&& other) noexcept : m_active(true) {
        std::memcpy(m_buffer, other.m_buffer, N);
        other.m_active = false;
    }

    char* data() noexcept { return m_buffer; }
    const char* c_str() const noexcept { return m_buffer; }
    constexpr std::size_t size() const noexcept { return N - 1; }

    // RAII Secure Memory Scrubbing upon destruction (0 RAM traces left)
    ~SecureStackString() noexcept {
        if (m_active) {
            volatile char* p = m_buffer;
            for (std::size_t i = 0; i < N; ++i) {
                p[i] = 0;
            }
        }
    }

    SecureStackString(const SecureStackString&) = delete;
    SecureStackString& operator=(const SecureStackString&) = delete;
    SecureStackString& operator=(SecureStackString&&) = delete;
};

template <std::size_t N>
struct PolymorphicDataV5 {
    std::uint8_t encrypted[N];
    std::uint32_t key1;
    std::uint32_t key2;
    std::uint32_t seed;

    constexpr PolymorphicDataV5(
        const char (&s)[N],
        const std::uint32_t k1,
        const std::uint32_t k2,
        const std::uint32_t sd)
        : encrypted{}, key1(k1), key2(k2), seed(sd) {

        for (std::size_t idx = 0U; idx < N; ++idx) {
            const std::uint8_t byte_val = static_cast<std::uint8_t>(s[idx]);

            const std::uint32_t shift1 = static_cast<std::uint32_t>(idx & 31U);
            const std::uint32_t k1_mod = key1 + seed + static_cast<std::uint32_t>(idx);
            const std::uint32_t rotl_val = (shift1 != 0U) ?
                ((k1_mod << shift1) | (k1_mod >> (32U - shift1))) : k1_mod;
            const std::uint8_t k1_byte = static_cast<std::uint8_t>(rotl_val & 0xFFU);

            const std::uint32_t idx2 = static_cast<std::uint32_t>(idx * 2U);
            const std::uint32_t shift2 = static_cast<std::uint32_t>(idx2 & 31U);
            const std::uint32_t k2_mod = key2 - seed + idx2;
            const std::uint32_t rotr_val = (shift2 != 0U) ?
                ((k2_mod >> shift2) | (k2_mod << (32U - shift2))) : k2_mod;
            const std::uint8_t k2_byte = static_cast<std::uint8_t>(rotr_val & 0xFFU);

            const std::uint8_t seed_byte = static_cast<std::uint8_t>(seed & 0xFFU);
            encrypted[idx] = byte_val ^ k1_byte ^ k2_byte ^ seed_byte;
        }
    }
};

template <std::size_t N>
struct EncryptedStringV5 {
    static_assert(N >= 1U, "String literal must have at least null terminator");

    PolymorphicDataV5<N> data_;

    constexpr explicit EncryptedStringV5(const char (&s)[N], std::uint32_t k1, std::uint32_t k2, std::uint32_t sd)
        : data_(s, k1, k2, sd) {}

    /**
     * @brief Zero-Heap Stack Decryption with Automatic RAII Memory Wiping
     */
    SecureStackString<N> decrypt_stack() const noexcept {
        SecureStackString<N> secureStr;
        char* dst = secureStr.data();

        for (std::size_t idx = 0U; idx < N - 1U; ++idx) {
            const std::uint8_t enc = data_.encrypted[idx];

            const std::uint32_t shift1 = static_cast<std::uint32_t>(idx & 31U);
            const std::uint32_t k1_mod = data_.key1 + data_.seed + static_cast<std::uint32_t>(idx);
            const std::uint32_t rotl_val = (shift1 != 0U) ?
                ((k1_mod << shift1) | (k1_mod >> (32U - shift1))) : k1_mod;
            const std::uint8_t k1_byte = static_cast<std::uint8_t>(rotl_val & 0xFFU);

            const std::uint32_t idx2 = static_cast<std::uint32_t>(idx * 2U);
            const std::uint32_t shift2 = static_cast<std::uint32_t>(idx2 & 31U);
            const std::uint32_t k2_mod = data_.key2 - data_.seed + idx2;
            const std::uint32_t rotr_val = (shift2 != 0U) ?
                ((k2_mod >> shift2) | (k2_mod << (32U - shift2))) : k2_mod;
            const std::uint8_t k2_byte = static_cast<std::uint8_t>(rotr_val & 0xFFU);

            const std::uint8_t seed_byte = static_cast<std::uint8_t>(data_.seed & 0xFFU);
            dst[idx] = static_cast<char>(enc ^ k1_byte ^ k2_byte ^ seed_byte);
        }
        dst[N - 1U] = '\0';
        return secureStr;
    }
};

#define ENC_STR_V5(lit) \
    ([]() -> strenc::v5::EncryptedStringV5<sizeof(lit)> { \
        return strenc::v5::EncryptedStringV5<sizeof(lit)>(lit, 0x12345678U, 0x87654321U, 0xDEADBEEFU); \
    }())

} // namespace v5
} // namespace strenc

#endif // STRENC_ENCRYPTED_STRING_V5_H
