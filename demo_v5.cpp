#include <iostream>
#include "encrypted_string_v5.h"

void printSecretString() {
    constexpr auto secretEncrypted = ENC_STR_V5("WindowsKernelSecurityPass2026");
    
    // In-place stack decryption with auto zero-wipe on scope exit
    auto decrypted = secretEncrypted.decrypt_stack();
    std::cout << "[+] Decrypted String on Stack: " << decrypted.c_str() << std::endl;
} // 'decrypted' destructor runs here: memory is 100% zero-wiped on stack!

int main() {
    std::cout << "========================================================\n";
    std::cout << " Stringo v5 Zero-Heap Stack Encryption & Auto-Wipe Demo \n";
    std::cout << "========================================================\n\n";

    printSecretString();

    std::cout << "[+] Function exited: Stack memory scrubbed!\n";
    return 0;
}
