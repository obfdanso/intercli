// The server library on its own ports: start, stop, restart, busy ports.

#include "secure_server.h"
#include "chat_client.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

using namespace SecureComm;

static int failures = 0;

static void check(bool condition, const std::string& what) {
    if (condition) {
        std::cout << "  PASS: " << what << std::endl;
    } else {
        std::cout << "  FAIL: " << what << std::endl;
        ++failures;
    }
}

static long long ms_since(std::chrono::steady_clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t).count();
}

// A server running on its own thread for the length of a scope.
struct Running {
    SecureServer server;
    std::thread thread;
    bool ok = false;
    explicit Running(ServerOptions options) : server(std::move(options)) {
        std::string error;
        ok = server.start(&error);
        if (ok) {
            thread = std::thread([this] { server.run(); });
        }
    }
    ~Running() {
        server.stop();
        if (thread.joinable()) thread.join();
    }
};

int main() {
    const uint16_t port = 18090;

    std::cout << "Start and stop" << std::endl;
    {
        ServerOptions options;
        options.port = port;
        Running r(options);
        check(r.ok, "server starts on a free port");
        check(r.server.port() == port, "server reports its port");
        check(r.server.people() == 0, "nobody is registered yet");

        std::cout << "Busy port" << std::endl;
        ServerOptions second;
        second.port = port;
        SecureServer other(second);
        std::string error;
        check(!other.start(&error), "a second server cannot take a port in use");
        check(error.find("in use") != std::string::npos, "the reason says the port is in use");

        std::cout << "People count" << std::endl;
        std::mutex m;
        std::condition_variable cv;
        bool registered = false;
        ChatEvents ev;
        ev.on_registered = [&](const std::string&) {
            { std::lock_guard<std::mutex> lock(m); registered = true; }
            cv.notify_all();
        };
        ChatClient client(ev);
        std::string err;
        check(client.connect("127.0.0.1", port, &err), "a client connects");
        client.request_name("ann");
        {
            std::unique_lock<std::mutex> lock(m);
            cv.wait_for(lock, std::chrono::seconds(5), [&] { return registered; });
        }
        check(registered, "the client registers");
        check(r.server.people() == 1, "people counts the registered name");
        client.disconnect();

        const auto t = std::chrono::steady_clock::now();
        r.server.stop();
        if (r.thread.joinable()) r.thread.join();
        check(ms_since(t) < 1500, "stop returns promptly (" + std::to_string(ms_since(t)) + " ms)");
    }

    std::cout << "Restart on the same port" << std::endl;
    {
        ServerOptions options;
        options.port = port;
        Running again(options);
        check(again.ok, "the port is free again after stop");
    }

    if (failures == 0) {
        std::cout << "All server core tests passed" << std::endl;
        return 0;
    }
    std::cout << failures << " server core test(s) failed" << std::endl;
    return 1;
}
