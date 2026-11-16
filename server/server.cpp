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
#include <string>
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
    // Created exclusively and checked: two servers starting at once can't each
    // save a different key, and a half-written file is removed, not kept.
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return key;  // someone else just saved one; use ours for this run only
    }
    DWORD written = 0;
    const BOOL ok = WriteFile(file, wrapped.data(), static_cast<DWORD>(wrapped.size()), &written, nullptr) &&
                    written == wrapped.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if (!ok) {
        DeleteFileW(path.c_str());
    }
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

// What can be set when starting the server. The defaults are an open chat
// (no room code) on port 8080.
struct Settings {
    int port = SecureComm::DEFAULT_PORT;
    std::string room_code;
    int max_wrong_codes = 10;
    int lockout_seconds = 60;
};

void print_usage(const char* program) {
    std::cout << "Usage: " << program << " [options]\n"
              << "  --port N             port to listen on, 1-65535 (default 8080)\n"
              << "  --room-code CODE     only people who know CODE can join (default: open chat)\n"
              << "  --max-wrong-codes N  wrong room codes allowed per address before a lockout (default 10)\n"
              << "  --lockout SECONDS    length of the first lockout; each one after doubles (default 60)\n"
              << "  --help               show this text\n"
              << "The room code can also come from the INTERCLI_ROOM_CODE environment variable,\n"
              << "which keeps it off the command line where other programs could see it." << std::endl;
}

// A whole number within [low, high], or false.
bool parse_number(const std::string& text, int low, int high, int* out) {
    try {
        size_t used = 0;
        const int value = std::stoi(text, &used);
        if (used != text.size() || value < low || value > high) {
            return false;
        }
        *out = value;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// Applies one setting by name. False with a reason when the name or value is wrong.
bool apply_setting(const std::string& key, const std::string& value, Settings* settings, std::string* error) {
    if (key == "port") {
        if (!parse_number(value, 1, 65535, &settings->port)) {
            *error = "port must be a number from 1 to 65535";
            return false;
        }
    } else if (key == "room-code") {
        if (SecureComm::normalize_room_code(value).empty() ||
            SecureComm::normalize_room_code(value).size() >= SecureComm::MAX_NAME_LEN) {
            *error = "room-code must be 1 to 31 letters or digits";
            return false;
        }
        settings->room_code = value;
    } else if (key == "max-wrong-codes") {
        if (!parse_number(value, 1, 1000, &settings->max_wrong_codes)) {
            *error = "max-wrong-codes must be a number from 1 to 1000";
            return false;
        }
    } else if (key == "lockout") {
        if (!parse_number(value, 1, 3600, &settings->lockout_seconds)) {
            *error = "lockout must be a number of seconds from 1 to 3600";
            return false;
        }
    } else {
        *error = "unknown option: " + key;
        return false;
    }
    return true;
}

// Reads "--name value" and "--name=value" options. False with a reason on a mistake.
bool parse_arguments(int argc, char* argv[], Settings* settings, std::string* error) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg.rfind("--", 0) != 0) {
            *error = "unexpected argument: " + arg;
            return false;
        }
        std::string key = arg.substr(2);
        std::string value;
        const size_t equals = key.find('=');
        if (equals != std::string::npos) {
            value = key.substr(equals + 1);
            key = key.substr(0, equals);
        } else if (i + 1 < argc) {
            value = argv[++i];
        } else {
            *error = "--" + key + " needs a value";
            return false;
        }
        if (!apply_setting(key, value, settings, error)) {
            return false;
        }
    }
    return true;
}

} // namespace

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        }
    }

    Settings settings;
    std::string settings_error;
    if (const char* code = std::getenv("INTERCLI_ROOM_CODE")) {
        if (*code && !apply_setting("room-code", code, &settings, &settings_error)) {
            std::cerr << "INTERCLI_ROOM_CODE: " << settings_error << std::endl;
            return 2;
        }
    }
    if (!parse_arguments(argc, argv, &settings, &settings_error)) {
        std::cerr << settings_error << "\nTry --help" << std::endl;
        return 2;
    }

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
        options.port = static_cast<uint16_t>(settings.port);
        options.room_code = settings.room_code;
        options.max_wrong_codes_per_address = settings.max_wrong_codes;
        options.lockout = std::chrono::seconds(settings.lockout_seconds);
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
        std::cout << (settings.room_code.empty() ? "Open chat: anyone who can reach this server can join"
                                                 : "A room code is needed to join")
                  << std::endl;
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
