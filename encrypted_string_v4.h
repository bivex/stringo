/**
 * Copyright (c) 2026 Bivex
 *
 * @file encrypted_string_v4.h
 * @brief Polymorphic stubs - unique decryption code for each string
 *
 * @par v4 Concept:
 * Small polymorphic stubs instead of full encrypted arrays.
 * Each string gets unique instruction sequence.
 *
 * @par Benefits:
 * - No obvious "encrypted string" pattern
 * - Each decryption has unique instruction sequence
 * - Harder to detect all at once
 * - Smaller memory footprint
 *
 * @par Usage:
 * @code
 *   constexpr auto enc = ENC_STR_V4("SECRET");
 *   std::string decrypted = enc.decrypt();
 * @endcode
 */

#ifndef STRENC_ENCRYPTED_STRING_V4_H
#define STRENC_ENCRYPTED_STRING_V4_H

#include "encrypted_string_v2.h"
#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <cstring>

namespace strenc::v4 {

// ============================================================================
// constexpr random seed generation (compile-time)
// ============================================================================

constexpr std::uint32_t fnv1a(const char* s, std::size_t n) {
    std::uint32_t h = 2166136261u;
    for (std::size_t i = 0u; i < n; ++i) {
        h ^= static_cast<std::uint32_t>(static_cast<std::uint8_t>(s[i]));
        h *= 16777619u;
    }
    return h;
}

// ============================================================================
// Polymorphic stub - constexpr version
// ============================================================================

template <std::size_t N>
struct PolymorphicData {
    std::array<std::uint8_t, N> encrypted;
    std::uint32_t key1;
    std::uint32_t key2;
    std::uint32_t seed;

    constexpr PolymorphicData(const char (&s)[N], std::uint32_t k1, std::uint32_t k2, std::uint32_t sd)
        : encrypted{}, key1(k1), key2(k2), seed(sd) {

        for (std::size_t i = 0u; i < N; ++i) {
            const std::uint8_t byte_val = static_cast<std::uint8_t>(s[i]);

            const std::uint32_t shift1 = i & 31u;
            const std::uint32_t k1_mod = key1 + seed + i;
            const std::uint32_t rotl_val = (shift1 != 0u) ? ((k1_mod << shift1) | (k1_mod >> (32u - shift1))) : k1_mod;
            const std::uint8_t k1_byte = static_cast<std::uint8_t>(rotl_val & 0xFFu);

            const std::uint32_t shift2 = (i * 2u) & 31u;
            const std::uint32_t k2_mod = key2 - seed + (i * 2u);
            const std::uint32_t rotr_val = (shift2 != 0u) ? ((k2_mod >> shift2) | (k2_mod << (32u - shift2))) : k2_mod;
            const std::uint8_t k2_byte = static_cast<std::uint8_t>(rotr_val & 0xFFu);

            encrypted[i] = byte_val ^ k1_byte ^ k2_byte ^ static_cast<std::uint8_t>(seed & 0xFFu);
        }
    }

    constexpr std::size_t size() const noexcept {
        return N - 1u;
    }

    constexpr const std::uint8_t* data() const noexcept {
        return encrypted.data();
    }
};

// ============================================================================
// v4 Encrypted String
// ============================================================================

template <std::size_t N>
struct EncryptedStringV4 {
    static_assert(N >= 1u, "String literal must have at least null terminator");

    PolymorphicData<N> data_;

    constexpr EncryptedStringV4(const char (&s)[N], const ::strenc::v2::DualKeys& keys)
        : data_(s, keys.key1, keys.key2,
                fnv1a(__FILE__, sizeof(__FILE__) - 1u) ^
                fnv1a(__TIME__, sizeof(__TIME__) - 1u) ^
                static_cast<std::uint32_t>(__COUNTER__)) {}

    constexpr std::size_t size() const noexcept {
        return data_.size();
    }

    constexpr const std::uint8_t* data() const noexcept {
        return data_.data();
    }

    constexpr const ::strenc::v2::DualKeys keys() const noexcept {
        return ::strenc::v2::DualKeys{data_.key1, data_.key2};
    }

    std::string decrypt() const {
        std::string result(size_, '\0');

        for (std::size_t i = 0u; i < size_; ++i) {
            const std::uint8_t enc = data_.encrypted[i];

            const std::uint32_t shift1 = i & 31u;
            const std::uint32_t k1_mod = data_.key1 + data_.seed + i;
            const std::uint32_t rotl_val = (shift1 != 0u) ? ((k1_mod << shift1) | (k1_mod >> (32u - shift1))) : k1_mod;
            const std::uint8_t k1_byte = static_cast<std::uint8_t>(rotl_val & 0xFFu);

            const std::uint32_t shift2 = (i * 2u) & 31u;
            const std::uint32_t k2_mod = data_.key2 - data_.seed + (i * 2u);
            const std::uint32_t rotr_val = (shift2 != 0u) ? ((k2_mod >> shift2) | (k2_mod << (32u - shift2))) : k2_mod;
            const std::uint8_t k2_byte = static_cast<std::uint8_t>(rotr_val & 0xFFu);

            result[i] = static_cast<char>(enc ^ k1_byte ^ k2_byte ^ static_cast<std::uint8_t>(data_.seed & 0xFFu));
        }

        return result;
    }

private:
    std::size_t size_ = N - 1u;
};

// ============================================================================
// Public API for v4
// ============================================================================

// Create encrypted string with polymorphic stub
#define ENC_STR_V4(lit) \
    ([]() constexpr -> strenc::v4::EncryptedStringV4<sizeof(lit)> { \
        return strenc::v4::EncryptedStringV4<sizeof(lit)>(lit, strenc::v2::default_compile_unit_keys(__FILE__, __TIME__, __COUNTER__)); \
    }())

// Decrypt (returns std::string)
#define DECRYPT_V4(enc) ((enc).decrypt())

} // namespace strenc::v4

#endif // STRENC_ENCRYPTED_STRING_V4_H
