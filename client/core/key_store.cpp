#include "key_store.h"
#include "../../crypto/crypto_utils.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace SecureComm {

namespace {

// People remembered at most; past this, new ones are not written down.
constexpr size_t kMaxPeers = 5000;
// Numbers are written down every couple of seconds, not per message. After a
// restart ours skip ahead by more than could have been used in between.
constexpr std::chrono::seconds kSaveEvery(2);
constexpr uint64_t kCounterSkip = 10000000;

uint64_t number_from(const std::string& word) {
    try {
        return word.empty() || word.size() > 20 ? 0 : std::stoull(word);
    } catch (const std::exception&) {
        return 0;
    }
}

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

KeyStore::KeyStore(const std::string& path, const std::vector<uint8_t>& private_key)
    : path_(path), key_in_file_(false) {
    load();
    try {
        public_ = x25519_public_from_private(private_key);
        private_ = private_key;
    } catch (const std::exception&) {
        // Not a usable key: one that lasts this run, never written down.
        private_ = x25519_generate_private();
        public_ = x25519_public_from_private(private_);
    }
}

void KeyStore::load() {
    if (path_.empty()) {
        return;
    }
    std::ifstream in;
    try {
        in.open(std::filesystem::u8path(path_));
    } catch (const std::exception&) {
        return;
    }
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream words(line);
        std::string kind, a, b, c;
        words >> kind >> a >> b >> c;
        if (kind == "identity" && key_in_file_) {
            const std::vector<uint8_t> key = key_from_hex(a);
            try {
                if (!key.empty()) {
                    public_ = x25519_public_from_private(key);
                    private_ = key;
                }
            } catch (const std::exception&) {
            }
        } else if (kind == "counter") {
            counter_ = number_from(a) + kCounterSkip;
        } else if (kind == "floor") {
            floor_ = number_from(a);
        } else if (kind == "mark"&& a.size() == 64 && plain_word(a) && marks_.size() < kMaxPeers) {
            marks_[a] = number_from(b);
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
void KeyStore::save_locked() {
    unsaved_ = false;
    last_save_ = std::chrono::steady_clock::now();
    if (path_.empty()) {
        return;
    }
    std::error_code ignored;
    std::filesystem::path target;
    try {
        target = std::filesystem::u8path(path_);
    } catch (const std::exception&) {
        return;
    }
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
        if (key_in_file_) {
            out << "identity " << bytes_to_hex(private_) << '\n';
        }
        out << "counter " << counter_ << '\n';
        out << "floor " << floor_ << '\n';
        for (const auto& peer : peers_) {
            out << "peer " << peer.first << ' ' << bytes_to_hex(peer.second) << '\n';
        }
        for (const auto& mark : marks_) {
            out << "mark " << mark.first << ' ' << mark.second << '\n';
        }
        if (!out.flush()) {
            return;
        }
    }
    std::filesystem::rename(temp, target, ignored);
}

void KeyStore::save_soon_locked() {
    unsaved_ = true;
    if (std::chrono::steady_clock::now() - last_save_ > kSaveEvery) {
        save_locked();
    }
}

KeyStore::~KeyStore() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (unsaved_) {
        save_locked();
    }
}

uint64_t KeyStore::next_counter() {
    std::lock_guard<std::mutex> lock(mutex_);
    const uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    counter_ = (std::max)(counter_ + 1, now);
    save_soon_locked();
    return counter_;
}

bool KeyStore::newer(const std::vector<uint8_t>& sender_key, uint64_t counter) {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::string id = bytes_to_hex(sender_key);
    const auto it = marks_.find(id);
    if (counter <= floor_ || (it != marks_.end() && counter <= it->second)) {
        return false;
    }
    if (it == marks_.end() && marks_.size() >= kMaxPeers) {
        // Full: the sender heard from longest ago makes room, so newcomers
        // still count. Their mark becomes a floor for everyone, or a flood of
        // throwaway keys could push a real sender out and let their old
        // messages pass again. Numbers are times, so new messages are above it.
        const auto oldest = std::min_element(marks_.begin(), marks_.end(),
            [](const auto& x, const auto& y) { return x.second < y.second; });
        floor_ = (std::max)(floor_, oldest->second);
        marks_.erase(oldest);
    }
    marks_[id] = counter;
    save_soon_locked();
    return true;
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
