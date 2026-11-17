#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace SecureComm {

// This person's long-term key for end-to-end encryption, and the keys seen
// for other people, kept in one small text file. Safe to use from any thread.
class KeyStore {
public:
    // With an empty path nothing is saved: a new key every run, and nobody
    // is remembered.
    explicit KeyStore(const std::string& path = "");
    // For an app that keeps the private key somewhere safer itself (32 bytes):
    // the file then holds only other people's keys.
    KeyStore(const std::string& path, const std::vector<uint8_t>& private_key);
    ~KeyStore();
    KeyStore(const KeyStore&) = delete;
    KeyStore& operator=(const KeyStore&) = delete;

    std::vector<uint8_t> private_key() const;
    std::vector<uint8_t> public_key() const;

    enum class Seen { New, Same, Changed };
    // Records the key a person in a chat showed and says how it compares with
    // the one they had before. chat tells chats apart: the same name in two
    // chats is two people.
    Seen remember(const std::string& chat, const std::string& name, const std::vector<uint8_t>& key);
    // The key last recorded for that person; empty if there is none.
    std::vector<uint8_t> known(const std::string& chat, const std::string& name) const;

    // Sealed messages are numbered so that an old one cannot be delivered a
    // second time. The number for our next one: higher than any we used
    // before, also after a restart or with the clock set back.
    uint64_t next_counter();
    // Whether counter is higher than every one seen from the holder of that
    // key. If so it is remembered, and the same message will not pass again.
    bool newer(const std::vector<uint8_t>& sender_key, uint64_t counter);

private:
    void load();
    void save_locked();
    void save_soon_locked();

    std::string path_;
    bool key_in_file_ = true;
    mutable std::mutex mutex_;
    std::vector<uint8_t> private_;
    std::vector<uint8_t> public_;
    std::map<std::string, std::vector<uint8_t>> peers_;  // "chat name" -> key
    uint64_t counter_ = 0;                  // the last number we used
    std::map<std::string, uint64_t> marks_;  // sender key (hex) -> highest number seen
    bool unsaved_ = false;
    std::chrono::steady_clock::time_point last_save_{};
};

} // namespace SecureComm
