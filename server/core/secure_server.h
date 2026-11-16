#pragma once

// The chat server without a console: accepts clients, runs the secure
// handshake, relays chat messages between registered names. server.exe and the
// desktop app (when hosting a chat) both run it.

#include <chrono>
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
    // Wrong room codes allowed from one address (across all its connections)
    // before it is locked out; each further lockout lasts twice as long, up to
    // an hour.
    int max_wrong_codes_per_address = 10;
    std::chrono::seconds lockout = std::chrono::seconds(60);
    // When true, connections from this PC itself are never locked out. Off by
    // default: another user account on the same PC is otherwise limited like
    // anyone else.
    bool exempt_loopback = false;
    // IPv6 connections are taken from this PC and from the local network
    // (link-local and unique-local addresses) only. An IPv6 address is often
    // reachable from the whole internet, with no router in between hiding it
    // the way home routers hide IPv4, so anything wider must be switched on.
    bool allow_global_ipv6 = false;
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

    // Host controls. Safe from any thread while the server runs.
    // Removes someone from the chat: they are told why, then disconnected.
    // They can join again. False if nobody has that name.
    bool kick(const std::string& name);
    // Removes someone and keeps them out until the server stops: the name is
    // refused, and so is their address unless it is this PC's own.
    bool ban(const std::string& name);

    size_t people() const;  // registered names
    uint16_t port() const;
    std::vector<uint8_t> identity_public() const;

    struct Impl;

private:
    std::unique_ptr<Impl> impl_;
};

} // namespace SecureComm
