#include <iostream>
#include "encrypted_string_v7.h"

int main() {
    // One-time per-thread runtime cookie init (TEB::ArbitraryUserPointer)
    STRENC_V7_INIT();

    std::cout << "========================================================\n";
    std::cout << " Stringo v7 Dual-Layer Runtime-Keyed Encryption Demo    \n";
    std::cout << "========================================================\n\n";

    // Compile-time encrypted strings (layer 1 only in .rdata — no plaintext)
    constexpr auto enc1 = ENC_STR_V7("NtOpenProcess");
    constexpr auto enc2 = ENC_STR_V7("SeDebugPrivilege");
    constexpr auto enc3 = ENC_USTR_V7(L"\\Device\\PhysicalMemory");

    // Runtime decrypt (layer 1 + layer 2 cookie from TEB StackBase^StackLimit^QPC)
    {
        auto s1 = DECRYPT_V7(enc1);
        auto s2 = DECRYPT_V7(enc2);
        auto s3 = DECRYPT_V7(enc3);

        std::cout << "[+] ANSI  decrypt: " << s1.c_str() << "\n";
        std::cout << "[+] ANSI  decrypt: " << s2.c_str() << "\n";

        UNICODE_STRING ustr = s3.to_unicode_string();
        std::wcout << L"[+] USTR  decrypt: " << ustr.Buffer << L"\n";
        std::cout  << "    Length=" << ustr.Length << " MaxLen=" << ustr.MaximumLength << "\n";

    } // <-- all three SecureStackStrings wiped here (volatile zero)

    std::cout << "\n[+] Scope exited: all decrypted buffers volatile-wiped from stack.\n";
    std::cout << "[+] Runtime cookie lives only in TEB::ArbitraryUserPointer — not in .data.\n";
    return 0;
}
