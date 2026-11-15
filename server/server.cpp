// server.exe: runs the chat server in a console. The server itself lives in
// server/core so the desktop app can host a chat with the same code.

#include "secure_server.h"
#include "../crypto/crypto_utils.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <dpapi.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

namespace {

// Set by the signal handler; main polls it so Ctrl+C actually stops the server.
std::atomic<bool> g_running(true);

// Only sets a flag: iostreams are not safe to use inside a signal handler.
void signal_handler(int) {
    g_running = false;
}

// The server's long-term identity, kept in the user's own settings folder so
// clients that joined before recognise it after a restart. On Windows the
// stored copy is wrapped with DPAPI (only this Windows user can unwrap it); on
// other systems it is created owner-only and refused if anyone else could
// read or change it. If it can't be kept safely, a temporary identity is used.
#ifdef _WIN32
std::filesystem::path identity_path() {
    const char* appdata = std::getenv("APPDATA");
    return appdata ? std::filesystem::path(appdata) / "intercli" / "server.key" : std::filesystem::path();
}

std::vector<uint8_t> dpapi(const std::vector<uint8_t>& in, bool protect) {
    DATA_BLOB src = {static_cast<DWORD>(in.size()), const_cast<BYTE*>(in.data())};
    DATA_BLOB out = {};
    const BOOL ok = protect
        ? CryptProtectData(&src, L"intercli server identity", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)
        : CryptUnprotectData(&src, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out);
    if (!ok) {
        return {};
    }
    std::vector<uint8_t> result(out.pbData, out.pbData + out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return result;
}

std::vector<uint8_t> load_or_create_identity() {
    const std::filesystem::path path = identity_path();
    if (path.empty()) {
        return {};
    }
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        std::ifstream in(path, std::ios::binary);
        std::vector<uint8_t> wrapped((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        std::vector<uint8_t> key = dpapi(wrapped, false);
        if (key.size() == 32) {
            return key;
        }
        std::cerr << "Can't read the saved server identity; using a temporary one" << std::endl;
        return {};
    }
    std::filesystem::create_directories(path.parent_path(), ec);
    SecureComm::CryptoManager crypto;
    std::vector<uint8_t> key = crypto.generate_identity().private_raw;
    const std::vector<uint8_t> wrapped = dpapi(key, true);
    if (wrapped.empty()) {
        return key;  // use it for this run only
    }
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(wrapped.data()), static_cast<std::streamsize>(wrapped.size()));
    return key;
}
#else
std::filesystem::path identity_path() {
    const char* config = std::getenv("XDG_CONFIG_HOME");
    const char* home = std::getenv("HOME");
    if (config && *config) return std::filesystem::path(config) / "intercli" / "server.key";
    if (home && *home) return std::filesystem::path(home) / ".config" / "intercli" / "server.key";
    return {};
}

std::vector<uint8_t> load_or_create_identity() {
    const std::filesystem::path path = identity_path();
    if (path.empty()) {
        return {};
    }
    struct stat st {};
    if (lstat(path.c_str(), &st) == 0) {
        // Only a plain file of ours that nobody else can read or change.
        if (!S_ISREG(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 077) != 0) {
            std::cerr << "The saved server identity is not private; using a temporary one" << std::endl;
            return {};
        }
        std::ifstream in(path, std::ios::binary);
        std::vector<uint8_t> key((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (key.size() == 32) {
            return key;
        }
        std::cerr << "Can't read the saved server identity; using a temporary one" << std::endl;
        return {};
    }
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    chmod(path.parent_path().c_str(), 0700);
    SecureComm::CryptoManager crypto;
    std::vector<uint8_t> key = crypto.generate_identity().private_raw;
    // Created owner-only in one step; O_EXCL and O_NOFOLLOW refuse a planted file or link.
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return key;  // use it for this run only
    }
    const bool ok = write(fd, key.data(), key.size()) == static_cast<ssize_t>(key.size());
    close(fd);
    if (!ok) {
        unlink(path.c_str());
    }
    return key;
}
#endif

} // namespace

int main() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
#ifdef _WIN32
    // Ctrl+Break arrives as SIGBREAK on Windows.
    std::signal(SIGBREAK, signal_handler);
#else
    // A send to a client that has just disconnected raises SIGPIPE, whose default
    // action kills the whole server. The failed send is already handled.
    std::signal(SIGPIPE, SIG_IGN);
#endif

    try {
        SecureComm::ServerOptions options;
        options.identity_private = load_or_create_identity();
        options.log = [](const std::string& line, bool is_error) {
            (is_error ? std::cerr : std::cout) << line << std::endl;
        };
        SecureComm::SecureServer server(options);

        std::string error;
        if (!server.start(&error)) {
            std::cerr << "Failed to start server" << std::endl;
            return 1;
        }

        std::cout << "Secure Communication Server" << std::endl;
        std::cout << "Features:" << std::endl;
        std::cout << "- Diffie-Hellman key exchange (new keys for every connection)" << std::endl;
        std::cout << "- Server identity proven with an Ed25519 signature" << std::endl;
        std::cout << "- AES-256-GCM encryption, with altered or replayed messages rejected" << std::endl;
        std::cout << "- Automatic key rotation" << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;

        std::thread runner([&server] { server.run(); });
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        server.stop();
        runner.join();
        std::cout << "Shutting down..." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
