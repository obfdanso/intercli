// Regression test for AES-256-GCM authenticated encryption.
// Guards against the bug where the GCM tag was never produced on encrypt nor
// verified on decrypt, which made every decrypt fail with "Failed to finalize decryption"
// and left the ciphertext unauthenticated.

#include "crypto_utils.h"
#include <iostream>
#include <string>
#include <vector>

using namespace SecureComm;

static int failures = 0;

static void check(bool condition, const std::string& what) {
    if (condition) {
        std::cout << "  PASS: " << what << std::endl;
    } else {
        std::cout << "  FAIL: " << what << std::endl;
        ++failures;
    }
}

int main() {
    CryptoManager crypto;

    try {
        std::vector<uint8_t> key = crypto.generate_symmetric_key(KEY_SIZE);
        std::vector<uint8_t> iv = crypto.generate_random_bytes(IV_SIZE);

        const std::string message = "Hello secure world";
        std::vector<uint8_t> plaintext(message.begin(), message.end());

        std::cout << "Round trip" << std::endl;
        std::vector<uint8_t> ciphertext = crypto.encrypt_aes_gcm(plaintext, key, iv);

        check(ciphertext.size() == plaintext.size() + GCM_TAG_SIZE,
              "ciphertext carries the appended GCM tag");
        check(ciphertext != plaintext, "ciphertext differs from plaintext");

        std::vector<uint8_t> recovered = crypto.decrypt_aes_gcm(ciphertext, key, iv);
        check(recovered == plaintext, "decrypt recovers the original plaintext");

        std::cout << "Tamper detection" << std::endl;
        std::vector<uint8_t> tampered = ciphertext;
        tampered[0] ^= 0x01;
        bool rejected = false;
        try {
            crypto.decrypt_aes_gcm(tampered, key, iv);
        } catch (const std::exception&) {
            rejected = true;
        }
        check(rejected, "modified ciphertext is rejected");

        std::vector<uint8_t> bad_tag = ciphertext;
        bad_tag[bad_tag.size() - 1] ^= 0x01;
        rejected = false;
        try {
            crypto.decrypt_aes_gcm(bad_tag, key, iv);
        } catch (const std::exception&) {
            rejected = true;
        }
        check(rejected, "modified authentication tag is rejected");

        std::vector<uint8_t> wrong_key = crypto.generate_symmetric_key(KEY_SIZE);
        rejected = false;
        try {
            crypto.decrypt_aes_gcm(ciphertext, wrong_key, iv);
        } catch (const std::exception&) {
            rejected = true;
        }
        check(rejected, "decryption under the wrong key is rejected");

    } catch (const std::exception& e) {
        std::cout << "  FAIL: unexpected exception: " << e.what() << std::endl;
        ++failures;
    }

    if (failures == 0) {
        std::cout << "All AES-GCM tests passed" << std::endl;
        return 0;
    }
    std::cout << failures << " AES-GCM test(s) failed" << std::endl;
    return 1;
}
