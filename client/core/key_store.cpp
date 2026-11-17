#include "key_store.h"
#include "../../crypto/crypto_utils.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace SecureComm {

namespace {

// People remembered at most; past this, new ones are not written down.
constexpr size_t kMaxPeers = 5000;

bool plain_word(const std::string& word) {
    if (word.empty() || word.size() > 128) {
        return false;
    }
    for (unsigned char c : word) {
        if (c < 0x21 || c > 0x7E) {
            return false;
        }
    }
    return true;
}

std::vector<uint8_t> key_from_hex(const std::string& hex) {
    if (hex.size() != 64) {
        return {};
    }
    try {
        return hex_to_bytes(hex);
    } catch (const std::exception&) {
        return {};
    }
}

} // namespace

KeyStore::KeyStore(const std::string& path) : path_(path) {
    load();
    if (private_.empty()) {
        private_ = x25519_generate_private();
        public_ = x25519_public_from_private(private_);
        std::lock_guard<std::mutex> lock(mutex_);
        save_locked();
    }
}

void KeyStore::load() {
    if (path_.empty()) {
        return;
    }
    std::ifstream in(path_);
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream words(line);
        std::string kind, a, b, c;
        words >> kind >> a >> b >> c;
        if (kind == "identity") {
            const std::vector<uint8_t> key = key_from_hex(a);
            try {
                if (!key.empty()) {
                    public_ = x25519_public_from_private(key);
                    private_ = key;
                }
            } catch (const std::exception&) {
            }
        } else if (kind == "peer" && plain_word(a) && plain_word(b) && peers_.size() < kMaxPeers) {
            const std::vector<uint8_t> key = key_from_hex(c);
            if (!key.empty()) {
                peers_[a + ' ' + b] = key;
            }
        }
    }
}

// Written to a second file first and swapped in, so a crash part-way never
// leaves a half-written key behind.
void KeyStore::save_locked() const {
    if (path_.empty()) {
        return;
    }
    std::error_code ignored;
    const std::filesystem::path target = std::filesystem::u8path(path_);
    if (target.has_parent_path()) {
        std::filesystem::create_directories(target.parent_path(), ignored);
    }
    std::filesystem::path temp = target;
    temp += ".tmp";
    {
        std::ofstream out(temp, std::ios::trunc);
        if (!out) {
            return;
        }
        // Only this user may read it (this does nothing on Windows, where the
        // user's own folders are already private).
        std::filesystem::permissions(temp, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                     ignored);
        out << "identity " << bytes_to_hex(private_) << '\n';
        for (const auto& peer : peers_) {
            out << "peer " << peer.first << ' ' << bytes_to_hex(peer.second) << '\n';
        }
        if (!out.flush()) {
            return;
        }
    }
    std::filesystem::rename(temp, target, ignored);
}

std::vector<uint8_t> KeyStore::private_key() const {
    return private_;
}

std::vector<uint8_t> KeyStore::public_key() const {
    return public_;
}

KeyStore::Seen KeyStore::remember(const std::string& chat, const std::string& name,
                                  const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::string id = chat + ' ' + name;
    const auto it = peers_.find(id);
    if (it != peers_.end() && it->second == key) {
        return Seen::Same;
    }
    const Seen seen = it == peers_.end() ? Seen::New : Seen::Changed;
    if (it != peers_.end() || peers_.size() < kMaxPeers) {
        peers_[id] = key;
        if (plain_word(chat) && plain_word(name)) {
            save_locked();
        }
    }
    return seen;
}

std::vector<uint8_t> KeyStore::known(const std::string& chat, const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = peers_.find(chat + ' ' + name);
    return it == peers_.end() ? std::vector<uint8_t>() : it->second;
}

} // namespace SecureComm
