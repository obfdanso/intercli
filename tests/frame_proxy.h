#pragma once

// A man in the middle for tests: listens on a local port, forwards one client's
// length-framed traffic to the real server and back, and on request alters it
// the way an attacker on the network could (tamper, replay, inject, truncate).

#include "common.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

class FrameProxy {
public:
#ifdef _WIN32
    using sock = SOCKET;
#else
    using sock = int;
#endif

    explicit FrameProxy(uint16_t target_port) : target_port_(target_port) {
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
        listener_ = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(listener_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        listen(listener_, 1);
        socklen_t len = sizeof(addr);
        getsockname(listener_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        accept_thread_ = std::thread([this] { accept_one(); });
    }

    ~FrameProxy() {
        stop_ = true;
        close_sock(listener_);
        close_sock(client_);
        close_sock(server_);
        if (accept_thread_.joinable()) accept_thread_.join();
        if (up_.joinable()) up_.join();
        if (down_.joinable()) down_.join();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    uint16_t port() const { return port_; }

    // Flip one ciphertext byte in the next encrypted frame going to the server.
    void tamper_next_to_server() { tamper_up_ = true; }
    // Send the last encrypted frame the client sent to the server again.
    void replay_last_to_server() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!last_up_.empty()) send_frame(server_, last_up_);
    }
    // Inject a key-rotation frame with no valid encrypted body into the client's stream.
    void inject_rotation_to_client() {
        SecureComm::MessageHeader h{};
        h.version = SecureComm::ProtocolVersion::V2_0;
        h.type = SecureComm::MessageType::KEY_ROTATION;
        h.sequence_number = 999;
        std::vector<uint8_t> frame = SecureComm::serialize_header(h);
        std::lock_guard<std::mutex> lock(mutex_);
        send_frame(client_, frame);
    }
    // Send the client a frame too short to hold a header.
    void truncate_to_client() {
        std::lock_guard<std::mutex> lock(mutex_);
        send_frame(client_, std::vector<uint8_t>{1, 2, 3});
    }

private:
    static void close_sock(sock s) {
#ifdef _WIN32
        if (s != INVALID_SOCKET) closesocket(s);
#else
        if (s >= 0) close(s);
#endif
    }

    static bool read_all(sock s, uint8_t* p, size_t n) {
        size_t got = 0;
        while (got < n) {
            const int r = recv(s, reinterpret_cast<char*>(p + got), static_cast<int>(n - got), 0);
            if (r <= 0) return false;
            got += static_cast<size_t>(r);
        }
        return true;
    }

    static bool read_frame(sock s, std::vector<uint8_t>* out) {
        uint32_t be = 0;
        if (!read_all(s, reinterpret_cast<uint8_t*>(&be), 4)) return false;
        const uint32_t n = ntohl(be);
        if (n > SecureComm::MAX_FRAME_SIZE) return false;
        out->assign(n, 0);
        return n == 0 || read_all(s, out->data(), n);
    }

    static void send_frame(sock s, const std::vector<uint8_t>& frame) {
        const uint32_t be = htonl(static_cast<uint32_t>(frame.size()));
        send(s, reinterpret_cast<const char*>(&be), 4, 0);
        if (!frame.empty()) send(s, reinterpret_cast<const char*>(frame.data()), static_cast<int>(frame.size()), 0);
    }

    static bool is_encrypted(const std::vector<uint8_t>& f) {
        return f.size() > sizeof(SecureComm::MessageHeader) &&
               SecureComm::deserialize_header(f).type == SecureComm::MessageType::ENCRYPTED_MESSAGE;
    }

    void accept_one() {
        client_ = accept(listener_, nullptr, nullptr);
        if (stop_) return;
        server_ = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(target_port_);
        connect(server_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        up_ = std::thread([this] { pump(client_, server_, true); });
        down_ = std::thread([this] { pump(server_, client_, false); });
    }

    void pump(sock from, sock to, bool upstream) {
        std::vector<uint8_t> frame;
        while (!stop_ && read_frame(from, &frame)) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (upstream && is_encrypted(frame)) {
                last_up_ = frame;
                if (tamper_up_.exchange(false)) {
                    // Inside the encrypted body, after the session id, message id and IV.
                    frame[sizeof(SecureComm::MessageHeader) + 4 + 4 + SecureComm::IV_SIZE + 2] ^= 0x40;
                }
            }
            send_frame(to, frame);
        }
#ifdef _WIN32
        shutdown(to, SD_BOTH);
#else
        shutdown(to, SHUT_RDWR);
#endif
    }

    uint16_t target_port_;
    uint16_t port_ = 0;
#ifdef _WIN32
    sock listener_ = INVALID_SOCKET, client_ = INVALID_SOCKET, server_ = INVALID_SOCKET;
#else
    sock listener_ = -1, client_ = -1, server_ = -1;
#endif
    std::thread accept_thread_, up_, down_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> tamper_up_{false};
    std::mutex mutex_;
    std::vector<uint8_t> last_up_;
};
