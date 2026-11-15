// server.exe: runs the chat server in a console. The server itself lives in
// server/core so the desktop app can host a chat with the same code.

#include "secure_server.h"

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
