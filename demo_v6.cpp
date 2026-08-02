#include <iostream>
#include "encrypted_string_v6.h"

void testKernelUnicodeExport() {
    // 1. Encrypt Wide WCHAR string L"\\Device\\HarddiskVolume1\\Windows\\System32\\ntoskrnl.exe"
    constexpr auto ustrEncrypted = ENC_USTR_V6(L"\\Device\\HarddiskVolume1\\Windows\\System32\\ntoskrnl.exe");

    // 2. Decrypt on stack with zero-heap allocation
    auto ustrStack = ustrEncrypted.decrypt_stack();

    // 3. Export directly into native Windows UNICODE_STRING
    UNICODE_STRING ustr = ustrStack.to_unicode_string();

    std::wcout << L"[+] Decrypted UNICODE_STRING: " << ustr.Buffer << std::endl;
    std::cout  << "    - Length         : " << ustr.Length << " bytes\n";
    std::cout  << "    - MaximumLength  : " << ustr.MaximumLength << " bytes\n";
} // 'ustrStack' destructor runs here: 100% volatile memory zero-wiped on stack!

void testKernelAnsiExport() {
    // 1. Encrypt ASCII string "NtQuerySystemInformation"
    constexpr auto strEncrypted = ENC_STR_V6("NtQuerySystemInformation");

    // 2. Decrypt on stack
    auto strStack = strEncrypted.decrypt_stack();

    // 3. Export directly into native Windows STRING (ANSI_STRING)
    STRING astr = strStack.to_ansi_string();

    std::cout << "[+] Decrypted STRING (ANSI_STRING): " << astr.Buffer << std::endl;
    std::cout << "    - Length        : " << astr.Length << " bytes\n";
    std::cout << "    - MaximumLength : " << astr.MaximumLength << " bytes\n";
}

int main() {
    std::cout << "========================================================\n";
    std::cout << " Stringo v6 Native Windows Kernel String Encryption Demo\n";
    std::cout << "========================================================\n\n";

    testKernelUnicodeExport();
    std::cout << "\n";
    testKernelAnsiExport();

    std::cout << "\n[+] Function Exited: All Stack Strings Volatile Zero-Wiped!\n";
    return 0;
}
