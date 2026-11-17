// The file that keeps this person's end-to-end key and the keys seen for others.

#include "key_store.h"
#include "crypto_utils.h"
#include <cstdio>
#include <fstream>
#include <iostream>
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
        KeyStore a, b;
        check(a.public_key() != b.public_key(), "without a file every store has its own key");
    } catch (const std::exception& e) {
        check(false, std::string("no exception: ") + e.what());
    }
    std::remove(path.c_str());
    std::cout << (failures == 0 ? "All key store tests passed" : "Some key store tests failed") << std::endl;
    return failures == 0 ? 0 : 1;
}
