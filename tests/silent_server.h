#pragma once

// A TCP listener on 127.0.0.1 that never accepts or answers: connecting to it
// succeeds (the kernel completes the handshake) but no reply ever arrives, the
// way a hung or wrong server behaves. Used to test connect cancellation and
// the handshake timeout.

#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

class SilentServer {
public:
    SilentServer() {
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
        sock_ = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        bind(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        listen(sock_, 4);
        socklen_t len = sizeof(addr);
        getsockname(sock_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
    }

    ~SilentServer() {
#ifdef _WIN32
        closesocket(sock_);
        WSACleanup();
#else
        close(sock_);
#endif
    }

    uint16_t port() const { return port_; }

private:
#ifdef _WIN32
    SOCKET sock_;
#else
    int sock_;
#endif
    uint16_t port_ = 0;
};
