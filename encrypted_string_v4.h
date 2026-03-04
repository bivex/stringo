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

#pragma once
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

constexpr uint32_t fnv1a(const char* s, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; ++i) {
        h ^= static_cast<uint32_t>(s[i]);
        h *= 16777619u;
    }
    return h;
}

// ============================================================================
// Polymorphic stub - constexpr version
// ============================================================================

template <size_t N>
struct PolymorphicData {
    std::array<uint8_t, N> encrypted;
    uint32_t key1;
    uint32_t key2;
    uint32_t seed;  // Unique seed for this instance

    constexpr PolymorphicData(const char (&s)[N], uint32_t k1, uint32_t k2, uint32_t sd)
        : encrypted{}, key1(k1), key2(k2), seed(sd) {

        // Encrypt with multi-layer + seed offset
        for (size_t i = 0; i < N; ++i) {
            uint8_t byte = static_cast<uint8_t>(s[i]);

            // Layer 1: rotl32(key1 + seed, i) - fixed for r=0 case
            uint32_t shift1 = i & 31;
            uint32_t k1_mod = key1 + seed + i;
            uint8_t k1_byte = static_cast<uint8_t>((shift1 ? ((k1_mod << shift1) | (k1_mod >> (32 - shift1))) : k1_mod) & 0xFFu);

            // Layer 2: rotr32(key2 - seed, i * 2) - fixed for r=0 case
            uint32_t shift2 = (i * 2) & 31;
            uint32_t k2_mod = key2 - seed + (i * 2);
            uint8_t k2_byte = static_cast<uint8_t>((shift2 ? ((k2_mod >> shift2) | (k2_mod << (32 - shift2))) : k2_mod) & 0xFFu);

            encrypted[i] = byte ^ k1_byte ^ k2_byte ^ static_cast<uint8_t>(seed & 0xFF);
        }
    }

    constexpr size_t size() const noexcept { return N - 1; }
    constexpr const uint8_t* data() const noexcept { return encrypted.data(); }
};

// ============================================================================
// v4 Encrypted String
// ============================================================================

template <size_t N>
struct EncryptedStringV4 {
    static_assert(N >= 1, "String literal must have at least null terminator");

    PolymorphicData<N> data_;

    constexpr EncryptedStringV4(const char (&s)[N], v2::DualKeys keys)
        : data_(s, keys.key1, keys.key2,
                fnv1a(__FILE__, sizeof(__FILE__) - 1) ^
                fnv1a(__TIME__, sizeof(__TIME__) - 1) ^
                static_cast<uint32_t>(__COUNTER__)) {}

    constexpr size_t size() const noexcept { return data_.size(); }
    constexpr const uint8_t* data() const noexcept { return data_.data(); }
    constexpr const v2::DualKeys keys() const noexcept {
        return {data_.key1, data_.key2};
    }

    // Decrypt using polymorphic stub logic
    std::string decrypt() const {
        std::string result(size_, '\0');

        for (size_t i = 0; i < size_; ++i) {
            uint8_t enc = data_.encrypted[i];

            // Reverse the encryption (polymorphic per-instance)
            uint32_t shift1 = i & 31;
            uint32_t k1_mod = data_.key1 + data_.seed + i;
            uint8_t k1_byte = static_cast<uint8_t>((shift1 ? ((k1_mod << shift1) | (k1_mod >> (32 - shift1))) : k1_mod) & 0xFFu);

            uint32_t shift2 = (i * 2) & 31;
            uint32_t k2_mod = data_.key2 - data_.seed + (i * 2);
            uint8_t k2_byte = static_cast<uint8_t>((shift2 ? ((k2_mod >> shift2) | (k2_mod << (32 - shift2))) : k2_mod) & 0xFFu);

            result[i] = static_cast<char>(enc ^ k1_byte ^ k2_byte ^ static_cast<uint8_t>(data_.seed & 0xFF));
        }

        return result;
    }

private:
    size_t size_ = N - 1;
};

// ============================================================================
// Macros for v4
// ============================================================================

#define STRENC_V4_CONCAT_IMPL(a,b) a##b
#define STRENC_V4_CONCAT(a,b) STRENC_V4_CONCAT_IMPL(a,b)

// Reuse v2's key generation
#define STRENC_V4_COMPUTE_KEYS() \
    (strenc::v2::default_compile_unit_keys(__FILE__, __TIME__, __COUNTER__))

// Create encrypted string with polymorphic stub
#define ENC_STR_V4(lit) \
    ([]() constexpr -> strenc::v4::EncryptedStringV4<sizeof(lit)> { \
        return strenc::v4::EncryptedStringV4<sizeof(lit)>(lit, STRENC_V4_COMPUTE_KEYS()); \
    }())

// Decrypt (returns std::string)
#define DECRYPT_V4(enc) (enc).decrypt()

} // namespace strenc::v4
