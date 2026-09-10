// Regression test for DH key generation and exchange.
// Guards against the OpenSSL 3.x failure where generate_dh_keypair() was called
// without domain parameters and returned "Failed to generate DH key pair".

#include "crypto_utils.h"
#include <iostream>
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
        std::cout << "DH key pair generation" << std::endl;
        KeyPair alice = crypto.generate_dh_keypair();
        KeyPair bob = crypto.generate_dh_keypair();

        check(!alice.private_key.empty(), "alice private key is non-empty");
        check(!alice.public_key.empty(), "alice public key is non-empty");
        check(!bob.public_key.empty(), "bob public key is non-empty");
        check(alice.public_key != bob.public_key, "peers generate distinct public keys");

        std::cout << "Handshake message capacity (PEM key is " << alice.public_key.size()
                  << " bytes)" << std::endl;
        check(alice.public_key.size() > KEY_SIZE,
              "PEM public key is larger than KEY_SIZE, so it must not use that field");
        check(alice.public_key.size() <= MAX_PUBLIC_KEY_SIZE,
              "PEM public key fits in HandshakeMessage::public_key");

        std::cout << "DH key exchange" << std::endl;
        std::vector<uint8_t> alice_secret =
            crypto.perform_dh_key_exchange(alice.private_key, bob.public_key);
        std::vector<uint8_t> bob_secret =
            crypto.perform_dh_key_exchange(bob.private_key, alice.public_key);

        check(!alice_secret.empty(), "derived secret is non-empty");
        check(alice_secret == bob_secret, "both peers derive the same shared secret");

        std::cout << "Session key derivation" << std::endl;
        std::vector<uint8_t> salt = crypto.generate_random_bytes(16);
        std::vector<uint8_t> alice_key = crypto.derive_shared_secret(alice_secret, salt);
        std::vector<uint8_t> bob_key = crypto.derive_shared_secret(bob_secret, salt);

        check(alice_key == bob_key, "both peers derive the same session key");
        check(alice_key.size() == KEY_SIZE, "session key is KEY_SIZE bytes");

    } catch (const std::exception& e) {
        std::cout << "  FAIL: unexpected exception: " << e.what() << std::endl;
        ++failures;
    }

    if (failures == 0) {
        std::cout << "All DH tests passed" << std::endl;
        return 0;
    }
    std::cout << failures << " DH test(s) failed" << std::endl;
    return 1;
}
