#pragma once

// The chat server without a console: accepts clients, runs the secure
// handshake, relays chat messages between registered names. server.exe and the
// desktop app (when hosting a chat) both run it.

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "common.h"

namespace SecureComm {

struct ServerOptions {
    uint16_t port = DEFAULT_PORT;
    // Normalised room code; empty means anyone may join.
    std::string room_code;
    // The server's long-term identity (32-byte Ed25519 private key). Empty: a
    // temporary identity is made for this run.
    std::vector<uint8_t> identity_private;
    // One call per event line; is_error marks lines server.exe prints to stderr.
    std::function<void(const std::string& line, bool is_error)> log;
};

class SecureServer {
public:
    explicit SecureServer(ServerOptions options = ServerOptions());
    ~SecureServer();  // stops the server

    SecureServer(const SecureServer&) = delete;
    SecureServer& operator=(const SecureServer&) = delete;

    // Binds the port exclusively and starts listening. On failure returns false
    // and, if error is given, a reason (for example the port is in use).
    bool start(std::string* error);
    // Accepts clients until stop(). Blocking: run it on its own thread.
    void run();
    // Safe from any thread; run() returns within about half a second and every
    // client connection is closed before stop() returns.
    void stop();

    size_t people() const;  // registered names
    uint16_t port() const;
    std::vector<uint8_t> identity_public() const;

    struct Impl;

private:
    std::unique_ptr<Impl> impl_;
};

} // namespace SecureComm
