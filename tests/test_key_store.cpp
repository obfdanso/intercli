// The file that keeps this person's end-to-end key and the keys seen for others.

#include "key_store.h"
#include "crypto_utils.h"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

using namespace SecureComm;

static int failures = 0;

static void check(bool condition, const std::string& what) {
    std::cout << (condition ? "  PASS: " : "  FAIL: ") << what << std::endl;
    failures += condition ? 0 : 1;
}

int main() {
    const std::string path = "test_key_store.tmp.txt";
    std::remove(path.c_str());
    const std::vector<uint8_t> ama(32, 1), ama_new(32, 2);
    try {
        std::vector<uint8_t> first_public;
        {
            KeyStore store(path);
            first_public = store.public_key();
            check(store.private_key().size() == 32 && first_public.size() == 32, "a key is made on first use");
            check(store.remember("chat1", "ama", ama) == KeyStore::Seen::New, "a first key is new");
            check(store.remember("chat1", "ama", ama) == KeyStore::Seen::Same, "the same key again is the same");
            check(store.remember("chat2", "ama", ama_new) == KeyStore::Seen::New,
                  "the same name in another chat is someone else");
        }
        {
            KeyStore store(path);
            check(store.public_key() == first_public, "the key is the same after a restart");
            check(store.known("chat1", "ama") == ama, "people are remembered after a restart");
            check(store.remember("chat1", "ama", ama_new) == KeyStore::Seen::Changed, "a different key is noticed");
            check(store.known("chat1", "ama") == ama_new, "the newest key is the one kept");
            check(store.known("chat1", "kofi").empty(), "a stranger has no key");
        }
        {
            std::ofstream out(path, std::ios::trunc);
            out << "identity nonsense\npeer chat1\npeer chat1 ama zz\n\nrubbish line here now\n";
        }
        {
            KeyStore store(path);
            check(store.public_key().size() == 32 && store.public_key() != first_public,
                  "a damaged file gets a fresh key");
            check(store.known("chat1", "ama").empty(), "damaged lines are skipped");
        }
        {
            const std::vector<uint8_t> given = x25519_generate_private();
            {
                KeyStore store(path, given);
                check(store.private_key() == given, "a key kept elsewhere is used as given");
                store.remember("chat1", "kofi", ama);
            }
            std::ifstream in(path);
            const std::string all((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            check(all.find("identity") == std::string::npos && all.find("kofi") != std::string::npos,
                  "and never written to the file, which still remembers people");
        }
        {
            std::remove(path.c_str());
            uint64_t last = 0;
            {
                KeyStore store(path);
                const uint64_t one = store.next_counter();
                last = store.next_counter();
                check(last > one, "message numbers go up");
                check(store.newer(ama, 5) && store.newer(ama, 9), "a higher number from a sender passes");
                check(!store.newer(ama, 9) && !store.newer(ama, 7), "the same or a lower one does not");
                check(store.newer(ama_new, 7), "each sender is counted separately");
            }
            KeyStore store(path);
            check(store.next_counter() > last, "our numbers keep going up after a restart");
            check(!store.newer(ama, 9) && store.newer(ama, 10), "what was seen is remembered after a restart");
        }
        {
            // Flooding with throwaway keys must not make room for a real
            // sender's old message to pass again.
            std::remove(path.c_str());
            std::vector<uint8_t> real(32, 0);  // sorts first, so it is the first pushed out
            {
                KeyStore store(path);
                check(store.newer(real, 1000), "a real sender's message passes");
                for (int i = 1; i <= 5000; ++i) {
                    std::vector<uint8_t> junk(32, 0xEE);
                    junk[0] = static_cast<uint8_t>(i >> 8);
                    junk[1] = static_cast<uint8_t>(i);
                    store.newer(junk, 2000 + i);
                }
                check(!store.newer(real, 1000) && !store.newer(real, 500),
                      "after a flood of other keys, the real sender's old message still does not pass");
                check(store.newer(real, 100000), "a new message from them still does");
            }
            KeyStore store(path);
            check(!store.newer(std::vector<uint8_t>(32, 0x01), 1500), "the floor is remembered after a restart");
        }
#ifdef _WIN32
        {
            // On Windows the private key is wrapped for this Windows user, and
            // a key written plainly by an older version is wrapped on first use.
            const auto contents = [&] {
                std::ifstream in(path);
                return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            };
            std::remove(path.c_str());
            std::vector<uint8_t> pub;
            std::string secret;
            {
                KeyStore store(path);
                pub = store.public_key();
                secret = bytes_to_hex(store.private_key());
            }
            check(contents().find(secret) == std::string::npos && contents().find("identity-protected") != std::string::npos,
                  "the private key is not in the file as it is");
            check(KeyStore(path).public_key() == pub, "and the same key comes back next time");

            {
                std::ofstream plain(path, std::ios::trunc);
                plain << "identity " << secret << "\n";
            }
            check(KeyStore(path).public_key() == pub, "a plainly written key is still read");
            check(contents().find(secret) == std::string::npos, "and is wrapped from then on");
        }
#endif
        KeyStore a, b;
        check(a.public_key() != b.public_key(), "without a file every store has its own key");
    } catch (const std::exception& e) {
        check(false, std::string("no exception: ") + e.what());
    }
    std::remove(path.c_str());
    std::cout << (failures == 0 ? "All key store tests passed" : "Some key store tests failed") << std::endl;
    return failures == 0 ? 0 : 1;
}
