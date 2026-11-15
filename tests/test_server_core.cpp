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
#include <vector>

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

// Records what one client hears, so tests can wait for it.
struct Ears {
    std::mutex m;
    std::condition_variable cv;
    std::vector<std::string> events;
    bool lost = false;

    void add(const std::string& e) {
        { std::lock_guard<std::mutex> lock(m); events.push_back(e); }
        cv.notify_all();
    }
    bool wait(const std::string& e, int ms = 5000) {
        std::unique_lock<std::mutex> lock(m);
        return cv.wait_for(lock, std::chrono::milliseconds(ms), [&] {
            for (const auto& x : events) if (x == e) return true;
            return false;
        });
    }
    bool wait_lost(int ms) {
        std::unique_lock<std::mutex> lock(m);
        return cv.wait_for(lock, std::chrono::milliseconds(ms), [&] { return lost; });
    }
    bool heard(const std::string& e) {
        std::lock_guard<std::mutex> lock(m);
        for (const auto& x : events) if (x == e) return true;
        return false;
    }
    ChatEvents events_for() {
        ChatEvents ev;
        ev.on_registered = [this](const std::string& n) { add("registered:" + n); };
        ev.on_register_failed = [this](const std::string& r) { add("failed:" + r); };
        ev.on_broadcast = [this](const std::string& f, const std::string& t) { add("broadcast:" + f + ":" + t); };
        ev.on_disconnected = [this](const std::string&) {
            { std::lock_guard<std::mutex> lock(m); lost = true; }
            cv.notify_all();
        };
        return ev;
    }
};

static void room_code_tests() {
    const uint16_t port = 18091;
    ServerOptions options;
    options.port = port;
    options.room_code = "K7P29Q";
    Running r(options);
    check(r.ok, "a server with a room code starts");
    std::string err;

    Ears host_ears;
    ChatClient host(host_ears.events_for());
    host.connect("127.0.0.1", port, &err);
    host.request_name("host", "K7P29Q");
    check(host_ears.wait("registered:host"), "the right code joins");

    Ears typed_ears;
    ChatClient typed(typed_ears.events_for());
    typed.connect("127.0.0.1", port, &err);
    typed.request_name("typed", "k7p-29q");
    check(typed_ears.wait("registered:typed"), "the code is accepted however it is typed");

    Ears wrong_ears;
    ChatClient wrong(wrong_ears.events_for());
    wrong.connect("127.0.0.1", port, &err);
    wrong.request_name("intruder", "AAAAAA");
    check(wrong_ears.wait("failed:Wrong room code", 4000), "a wrong code is refused");
    host.send_broadcast("secret plans");
    check(typed_ears.wait("broadcast:host:secret plans"), "members hear broadcasts");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    check(!wrong_ears.heard("broadcast:host:secret plans"), "a refused connection hears nothing");

    Ears name_ears;
    ChatClient name_probe(name_ears.events_for());
    name_probe.connect("127.0.0.1", port, &err);
    name_probe.request_name("host", "AAAAAA");
    check(name_ears.wait("failed:Wrong room code", 4000),
          "a wrong code with a taken name still only says wrong code");

    Ears guess_ears;
    ChatClient guesser(guess_ears.events_for());
    guesser.connect("127.0.0.1", port, &err);
    for (int i = 0; i < 5; ++i) {
        guesser.request_name("guess" + std::to_string(i), "BBBBB" + std::to_string(i));
    }
    check(guess_ears.wait_lost(15000), "five wrong codes close the connection");

    std::cout << "Open server" << std::endl;
    ServerOptions open_options;
    open_options.port = 18092;
    Running open(open_options);
    Ears open_ears;
    ChatClient anyone(open_ears.events_for());
    anyone.connect("127.0.0.1", 18092, &err);
    anyone.request_name("anyone", "WHATEVER");
    check(open_ears.wait("registered:anyone"), "a server without a code ignores the code field");
}

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

    std::cout << "Room code" << std::endl;
    room_code_tests();

    if (failures == 0) {
        std::cout << "All server core tests passed" << std::endl;
        return 0;
    }
    std::cout << failures << " server core test(s) failed" << std::endl;
    return 1;
}
