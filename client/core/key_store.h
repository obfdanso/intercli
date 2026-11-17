#pragma once

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

    std::vector<uint8_t> private_key() const;
    std::vector<uint8_t> public_key() const;

    enum class Seen { New, Same, Changed };
    // Records the key a person in a chat showed and says how it compares with
    // the one they had before. chat tells chats apart: the same name in two
    // chats is two people.
    Seen remember(const std::string& chat, const std::string& name, const std::vector<uint8_t>& key);
    // The key last recorded for that person; empty if there is none.
    std::vector<uint8_t> known(const std::string& chat, const std::string& name) const;

private:
    void load();
    void save_locked() const;

    std::string path_;
    mutable std::mutex mutex_;
    std::vector<uint8_t> private_;
    std::vector<uint8_t> public_;
    std::map<std::string, std::vector<uint8_t>> peers_;  // "chat name" -> key
};

} // namespace SecureComm
