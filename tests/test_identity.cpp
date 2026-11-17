// Ed25519 server identity keys, safety codes and room codes.

#include "crypto_utils.h"
#include <iostream>
#include <set>
#include <string>

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
        std::cout << "End-to-end keys" << std::endl;
        {
            const std::vector<uint8_t> a = x25519_generate_private();
            const std::vector<uint8_t> b = x25519_generate_private();
            const std::vector<uint8_t> c = x25519_generate_private();
            const std::vector<uint8_t> a_pub = x25519_public_from_private(a);
            const std::vector<uint8_t> b_pub = x25519_public_from_private(b);
            check(a.size() == 32 && a_pub.size() == 32 && a != b, "keys are 32 bytes and differ");
            const std::vector<uint8_t> ab = e2e_shared_key(a, b_pub);
            check(ab.size() == 32 && ab == e2e_shared_key(b, a_pub), "both sides get the same key");
            check(ab != e2e_shared_key(c, a_pub), "a third person gets a different key");
            bool refused = false;
            try {
                e2e_shared_key(a, std::vector<uint8_t>(32, 0));
            } catch (const std::exception&) {
                refused = true;
            }
            check(refused, "an all-zero public key is refused");
            refused = false;
            try {
                e2e_shared_key(a, std::vector<uint8_t>(31, 1));
            } catch (const std::exception&) {
                refused = true;
            }
            check(refused, "a short public key is refused");
            check(pair_safety_code(a_pub, b_pub) == pair_safety_code(b_pub, a_pub) &&
                  pair_safety_code(a_pub, b_pub).size() == 24, "the pair's safety code is the same both ways");
        }

        std::cout << "Identity keys" << std::endl;
        IdentityKey id = crypto.generate_identity();
        check(id.private_raw.size() == 32 && id.public_raw.size() == 32, "keys are 32 bytes");
        check(crypto.identity_from_private(id.private_raw).public_raw == id.public_raw,
              "the public key is recovered from the private key");

        const std::string text = "intercli-handshake-v2 transcript";
        std::vector<uint8_t> msg(text.begin(), text.end());
        std::vector<uint8_t> sig = crypto.identity_sign(id, msg);
        check(sig.size() == 64, "signature is 64 bytes");
        check(crypto.identity_verify(id.public_raw, msg, sig), "a genuine signature verifies");

        std::vector<uint8_t> other_msg = msg;
        other_msg[0] ^= 1;
        check(!crypto.identity_verify(id.public_raw, other_msg, sig), "a changed message fails");
        std::vector<uint8_t> bad_sig = sig;
        bad_sig[10] ^= 1;
        check(!crypto.identity_verify(id.public_raw, msg, bad_sig), "a changed signature fails");
        IdentityKey other = crypto.generate_identity();
        check(!crypto.identity_verify(other.public_raw, msg, sig), "another key's check fails");
        check(!crypto.identity_verify(std::vector<uint8_t>(5, 1), msg, sig), "a malformed key fails safely");

        std::cout << "Safety code" << std::endl;
        const std::string code = safety_code(id.public_raw);
        check(code.size() == 24, "safety code is 5 groups of 4 digits");
        check(code == safety_code(id.public_raw), "safety code is stable");
        check(code != safety_code(other.public_raw), "different keys give different codes");

        std::cout << "Room codes" << std::endl;
        const std::string alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
        std::set<std::string> seen;
        bool all_valid = true;
        for (int i = 0; i < 200; ++i) {
            const std::string room = crypto.generate_room_code();
            seen.insert(room);
            all_valid = all_valid && room.size() == 6 &&
                        room.find_first_not_of(alphabet) == std::string::npos;
        }
        check(all_valid, "room codes are 6 characters from the unambiguous alphabet");
        check(seen.size() > 190, "room codes are random");
        check(normalize_room_code(" k7p-29q ") == "K7P29Q", "typed codes are normalised");
        check(format_room_code("K7P29Q") == "K7P-29Q", "codes are shown as XXX-XXX");
    } catch (const std::exception& e) {
        std::cout << "  FAIL: unexpected exception: " << e.what() << std::endl;
        ++failures;
    }

    if (failures == 0) {
        std::cout << "All identity tests passed" << std::endl;
        return 0;
    }
    std::cout << failures << " identity test(s) failed" << std::endl;
    return 1;
}
