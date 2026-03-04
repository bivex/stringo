/**
 * Copyright (c) 2026 Bivex
 *
 * Author: Bivex
 * Available for contact via email: support@b-b.top
 * For up-to-date contact information:
 * https://github.com/bivex
 *
 * Created: 2026-03-04 17:30
 * Last Updated: 2026-03-04 17:30
 *
 * Licensed under the MIT License.
 * Commercial licensing available upon request.
 */

/**
 * @file demo_v3.cpp
 * @brief Full demo and test for encrypted_string_v3.h
 */

#include "encrypted_string_v3.h"
#include <iostream>

int main() {
    std::cout << "=== String Encryption v3 Demo ===" << std::endl;
    std::cout << std::endl;

    // 1. Create encrypted string at compile time
    constexpr auto password = ENC_STR_V3("MySecretPassword123");
    std::cout << "1. Created encrypted string at compile time" << std::endl;
    std::cout << std::endl;

    // 2. Decrypt with stack allocation + memory obfuscation (recommended)
    std::cout << "2. Decrypt with memory obfuscation:" << std::endl;
    {
        AUTO_DECRYPT_V3(password);
        std::cout << "   Password: " << _dec_.c_str() << std::endl;
        std::cout << "   Memory contains obfuscated data (XORed with runtime key)" << std::endl;
    }
    std::cout << "   Buffer securely zeroed" << std::endl;
    std::cout << std::endl;

    // 3. Custom variable name
    std::cout << "3. Custom variable name:" << std::endl;
    {
        AUTO_DECRYPT_VAR_V3(decrypted, password);
        std::string s = decrypted.string();
        std::cout << "   Decrypted: " << s << std::endl;
    }
    std::cout << std::endl;

    // 4. Fast version (no memory obfuscation, slightly faster)
    std::cout << "4. Fast version (no memory obfuscation):" << std::endl;
    {
        AUTO_DECRYPT_V3_FAST(password);
        std::cout << "   Fast: " << _dec_.c_str() << std::endl;
    }
    std::cout << std::endl;

    // 5. Check allocation type
    std::cout << "5. Check allocation type:" << std::endl;
    {
        AUTO_DECRYPT_VAR_V3(guard, password);
        if (guard.is_on_stack()) {
            std::cout << "   Using stack allocation (small string)" << std::endl;
        } else {
            std::cout << "   Using heap allocation (large string)" << std::endl;
        }
    }
    std::cout << std::endl;

    // 6. Get runtime key for debugging
    std::cout << "6. Runtime key for debugging:" << std::endl;
    {
        AUTO_DECRYPT_VAR_V3(guard, password);
        std::cout << "   Runtime key: 0x" << std::hex << guard.runtime_key() << std::dec << std::endl;
    }
    std::cout << std::endl;

    // 7. Multiple strings in same scope
    std::cout << "7. Multiple strings:" << std::endl;
    {
        constexpr auto str1 = ENC_STR_V3("Hello");
        constexpr auto str2 = ENC_STR_V3("World");

        AUTO_DECRYPT_VAR_V3(dec1, str1);
        AUTO_DECRYPT_VAR_V3(dec2, str2);

        std::cout << "   " << dec1.c_str() << " " << dec2.c_str() << "!" << std::endl;
    }
    std::cout << std::endl;

    // 8. Test with empty string
    std::cout << "8. Empty string test:" << std::endl;
    {
        constexpr auto empty = ENC_STR_V3("");
        AUTO_DECRYPT_VAR_V3(dec_empty, empty);
        std::cout << "   Empty string: '" << dec_empty.c_str() << "' (length: " << empty.size() << ")" << std::endl;
    }
    std::cout << std::endl;

    // 9. Test size property
    std::cout << "9. Size property:" << std::endl;
    {
        constexpr auto test_str = ENC_STR_V3("Test123");
        std::cout << "   Encrypted size: " << test_str.size() << " bytes" << std::endl;
        AUTO_DECRYPT_V3(test_str);
        std::cout << "   Decrypted: " << _dec_.c_str() << std::endl;
    }
    std::cout << std::endl;

    std::cout << "=== All v3 tests passed ===" << std::endl;
    return 0;
}
