// Drives in-process ChatClients against a real server (started by run_with_server.sh).

#include "chat_client.h"
#include "silent_server.h"
#include "frame_proxy.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <memory>
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

// Records every event a client reports, so the test can wait for one to show up.
struct Recorder {
    std::mutex mutex;
    std::condition_variable cv;
    std::vector<std::string> events;
    int send_rotated = 0;
    int disconnected = 0;

    void add(const std::string& event) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            events.push_back(event);
        }
        cv.notify_all();
    }

    bool has(const std::string& event) {
        std::lock_guard<std::mutex> lock(mutex);
        for (const auto& e : events) {
            if (e == event) {
                return true;
            }
        }
        return false;
    }

    bool wait_for(const std::function<bool()>& pred, int ms = 5000) {
        std::unique_lock<std::mutex> lock(mutex);
        return cv.wait_for(lock, std::chrono::milliseconds(ms), [&] {
            lock.unlock();
            const bool ok = pred();
            lock.lock();
            return ok;
        });
    }

    bool wait_event(const std::string& event, int ms = 5000) {
        return wait_for([&] { return has(event); }, ms);
    }

    int count_prefix(const std::string& prefix) {
        std::lock_guard<std::mutex> lock(mutex);
        int n = 0;
        for (const auto& e : events) {
            if (e.rfind(prefix, 0) == 0) {
                ++n;
            }
        }
        return n;
    }

    ChatEvents make_events() {
        ChatEvents ev;
        ev.on_registered = [this](const std::string& n) { add("registered:" + n); };
        ev.on_register_failed = [this](const std::string& r) { add("register_failed:" + r); };
        ev.on_direct = [this](const std::string& f, const std::string& t) { add("direct:" + f + ":" + t); };
        ev.on_broadcast = [this](const std::string& f, const std::string& t) { add("broadcast:" + f + ":" + t); };
        ev.on_roster = [this](const std::vector<std::string>& names, const std::string&) {
            std::string joined;
            for (const auto& n : names) {
                joined += (joined.empty() ? "" : ",") + n;
            }
            add("roster:" + joined);
        };
        ev.on_presence = [this](const std::string& n, bool joined, const std::string&) {
            add(std::string("presence:") + n + (joined ? ":joined" : ":left"));
        };
        ev.on_notice = [this](const std::string& t) { add("notice:" + t); };
        ev.on_send_key_rotated = [this] {
            {
                std::lock_guard<std::mutex> lock(mutex);
                ++send_rotated;
            }
            cv.notify_all();
        };
        ev.on_disconnected = [this](const std::string&) {
            {
                std::lock_guard<std::mutex> lock(mutex);
                ++disconnected;
            }
            cv.notify_all();
        };
        return ev;
    }
};

static bool contains_prefix(Recorder& r, const std::string& prefix) {
    return r.count_prefix(prefix) > 0;
}

// Speaks protocol version 1 to the server: it must answer with an error frame
// and close, not carry on.
static bool old_version_hello_is_refused() {
#ifdef _WIN32
    using sock = SOCKET;
#else
    using sock = int;
#endif
    sock s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(DEFAULT_PORT);
    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;

    MessageHeader h{};
    h.version = ProtocolVersion::V1_0;
    h.type = MessageType::HANDSHAKE_INIT;
    h.payload_size = sizeof(HandshakeMessage);
    std::vector<uint8_t> frame = serialize_header(h);
    HandshakeMessage hs{};
    std::vector<uint8_t> body = serialize_handshake(hs);
    frame.insert(frame.end(), body.begin(), body.end());
    const uint32_t be = htonl(static_cast<uint32_t>(frame.size()));
    send(s, reinterpret_cast<const char*>(&be), 4, 0);
    send(s, reinterpret_cast<const char*>(frame.data()), static_cast<int>(frame.size()), 0);

    uint32_t len_be = 0;
    bool error_frame = false;
    if (recv(s, reinterpret_cast<char*>(&len_be), 4, MSG_WAITALL) == 4) {
        std::vector<uint8_t> reply(ntohl(len_be));
        if (!reply.empty() && recv(s, reinterpret_cast<char*>(reply.data()), static_cast<int>(reply.size()),
                                   MSG_WAITALL) == static_cast<int>(reply.size()) &&
            reply.size() >= sizeof(MessageHeader)) {
            error_frame = deserialize_header(reply).type == MessageType::ERROR_MESSAGE;
        }
    }
    char byte;
    const bool closed = recv(s, &byte, 1, 0) <= 0;
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
    return error_frame && closed;
}

int main() {
    Recorder alice_log;
    Recorder bob_log;
    ChatClient alice(alice_log.make_events());
    ChatClient bob(bob_log.make_events());
    std::string error;

    std::cout << "Connecting" << std::endl;
    check(alice.connect("127.0.0.1", DEFAULT_PORT, &error), "alice connects");
    check(bob.connect("localhost", DEFAULT_PORT, &error), "bob connects by host name");
    check(alice.connected() && bob.connected(), "both report connected");
    {
        Recorder six_log;
        ChatClient six(six_log.make_events());
        std::string six_error;
        check(six.connect("::1", DEFAULT_PORT, &six_error), "a client connects over IPv6");
        six.request_name("six");
        check(six_log.wait_event("registered:six"), "the IPv6 client registers");
    }
    // Without keepalive a silently dropped network (Wi-Fi off) would leave the
    // client showing online forever.
    check(alice.keepalive_enabled(), "keepalive is on for the connection");

    std::cout << "Registration" << std::endl;
    alice.request_name("alice");
    check(alice_log.wait_event("registered:alice"), "alice registers");
    bob.request_name("alice");
    check(bob_log.wait_for([&] { return contains_prefix(bob_log, "register_failed:"); }),
          "taken name is refused");
    {
        std::lock_guard<std::mutex> lock(bob_log.mutex);
        bool mentions_taken = false;
        for (const auto& e : bob_log.events) {
            if (e.rfind("register_failed:", 0) == 0 && e.find("taken") != std::string::npos) {
                mentions_taken = true;
            }
        }
        check(mentions_taken, "refusal reason mentions taken");
    }
    bob.request_name("bob");
    check(bob_log.wait_event("registered:bob"), "bob registers with a free name");
    check(alice_log.wait_event("presence:bob:joined"), "alice sees bob join");

    std::cout << "Roster" << std::endl;
    bob.request_roster();
    check(bob_log.wait_event("roster:alice,bob"), "roster lists alice and bob");

    std::cout << "Messages" << std::endl;
    check(bob.send_direct("alice", "hi \xF0\x9F\x91\x8B caf\xC3\xA9"), "direct send accepted");
    check(alice_log.wait_event("direct:bob:hi \xF0\x9F\x91\x8B caf\xC3\xA9"),
          "direct message with emoji arrives intact");
    check(bob.send_broadcast("all"), "broadcast send accepted");
    check(alice_log.wait_event("broadcast:bob:all"), "broadcast reaches alice");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    check(!bob_log.has("broadcast:bob:all"), "broadcast does not echo to sender");
    bob.send_direct("ghost", "x");
    check(bob_log.wait_event("notice:No such user: ghost"), "unknown recipient reported");

    std::cout << "Size limit" << std::endl;
    check(!bob.send_broadcast(std::string(MAX_TEXT_LEN + 1, 'a')), "1025 bytes is rejected");
    check(bob.send_broadcast(std::string(MAX_TEXT_LEN, 'b')), "1024 bytes is accepted");
    check(alice_log.wait_event("broadcast:bob:" + std::string(MAX_TEXT_LEN, 'b')),
          "1024-byte message arrives whole");

    std::cout << "Key rotation" << std::endl;
    // bob has sent 8 chat messages so far (REGISTER x2, WHO, the request for
    // alice's key, direct, broadcast, the request for ghost's key, 1024-byte
    // broadcast). The rejected one and the one to ghost never went out.
    const uint32_t before = bob.status().messages_until_rotation;
    check(before == KEY_ROTATION_INTERVAL - 8, "messages until rotation counts down");
    for (int i = 1; i <= 11; ++i) {
        bob.send_broadcast("filler-" + std::to_string(i));
    }
    check(alice_log.wait_for([&] { return alice_log.count_prefix("broadcast:bob:filler-") == 11; }),
          "all 11 messages arrive across the rotation");
    SessionStatus st = bob.status();
    check(st.send_rotations == 1, "one automatic rotation after crossing 10 sent");
    check(st.last_send_rotation.has_value(), "rotation time is recorded");
    check(st.messages_until_rotation == KEY_ROTATION_INTERVAL - (19 % KEY_ROTATION_INTERVAL),
          "counter restarts after the rotation");
    {
        std::lock_guard<std::mutex> lock(bob_log.mutex);
        check(bob_log.send_rotated == 1, "send key rotated callback fired once");
    }
    check(bob.rotate_send_key(), "manual rotation succeeds");
    check(bob.status().send_rotations == 2, "manual rotation is counted");
    bob.send_broadcast("after-rotation");
    check(alice_log.wait_event("broadcast:bob:after-rotation"), "traffic decrypts after manual rotation");

    std::cout << "Disconnect inside a callback" << std::endl;
    {
        Recorder carol_log;
        ChatEvents ev = carol_log.make_events();
        std::unique_ptr<ChatClient> carol;
        std::atomic<bool> done{false};
        ev.on_registered = [&](const std::string&) {
            carol->disconnect();
            done = true;
            carol_log.add("done");
        };
        carol = std::make_unique<ChatClient>(ev);
        check(carol->connect("127.0.0.1", DEFAULT_PORT, &error), "carol connects");
        carol->request_name("carol");
        check(carol_log.wait_event("done"), "disconnect from a callback returns");
        check(alice_log.wait_event("presence:carol:left"), "alice sees carol leave");
        carol.reset();
        check(done, "client destroyed cleanly afterwards");
    }

    std::cout << "Leaving" << std::endl;
    bob.disconnect();
    check(alice_log.wait_event("presence:bob:left"), "alice sees bob leave");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    {
        std::lock_guard<std::mutex> lock(bob_log.mutex);
        check(bob_log.disconnected == 0, "user disconnect does not report a lost connection");
    }
    check(!bob.connected(), "bob reports disconnected");

    std::cout << "Server identity" << std::endl;
    check(alice.server_identity().size() == 32, "the server proves a 32-byte identity key");
    {
        Recorder log;
        ChatClient wary(log.make_events());
        std::vector<uint8_t> wrong = alice.server_identity();
        wrong[0] ^= 0xFF;
        wary.set_expected_identity(wrong);
        std::string err;
        check(!wary.connect("127.0.0.1", DEFAULT_PORT, &err), "a different identity than expected is refused");
        check(err.find("identity has changed") != std::string::npos, "the refusal says the identity changed");
        ChatClient trusting(log.make_events());
        trusting.set_expected_identity(alice.server_identity());
        check(trusting.connect("127.0.0.1", DEFAULT_PORT, &err), "the expected identity is accepted");
    }

    std::cout << "Tampered frame" << std::endl;
    {
        FrameProxy proxy(DEFAULT_PORT);
        Recorder log;
        ChatClient carol2(log.make_events());
        std::string err;
        check(carol2.connect("127.0.0.1", proxy.port(), &err), "a client connects through the proxy");
        carol2.request_name("tamper");
        check(log.wait_event("registered:tamper"), "it registers through the proxy");
        check(alice_log.wait_event("presence:tamper:joined"), "alice sees it join");
        proxy.tamper_next_to_server();
        carol2.send_broadcast("altered on the way");
        check(alice_log.wait_event("presence:tamper:left"), "the server drops a client whose frame was altered");
        check(!alice_log.has("broadcast:tamper:altered on the way"), "the altered message is not relayed");
    }

    std::cout << "Replayed frame" << std::endl;
    {
        FrameProxy proxy(DEFAULT_PORT);
        Recorder log;
        ChatClient replayer(log.make_events());
        std::string err;
        check(replayer.connect("127.0.0.1", proxy.port(), &err), "a client connects through the proxy");
        replayer.request_name("replay");
        check(log.wait_event("registered:replay"), "it registers");
        replayer.send_broadcast("only once");
        check(alice_log.wait_event("broadcast:replay:only once"), "the message arrives");
        proxy.replay_last_to_server();
        check(alice_log.wait_event("presence:replay:left"), "the server drops a client whose frame was replayed");
        check(alice_log.count_prefix("broadcast:replay:only once") == 1, "the replayed message is not relayed twice");
    }

    std::cout << "Injected key rotation" << std::endl;
    {
        FrameProxy proxy(DEFAULT_PORT);
        Recorder log;
        ChatClient victim(log.make_events());
        std::string err;
        check(victim.connect("127.0.0.1", proxy.port(), &err), "a client connects through the proxy");
        victim.request_name("victim");
        check(log.wait_event("registered:victim"), "it registers");
        proxy.inject_rotation_to_client();
        check(log.wait_for([&] { std::lock_guard<std::mutex> l(log.mutex); return log.disconnected > 0; }),
              "a forged rotation ends the connection instead of silently changing keys");
    }

    std::cout << "Truncated frame" << std::endl;
    {
        FrameProxy proxy(DEFAULT_PORT);
        Recorder log;
        ChatClient victim(log.make_events());
        std::string err;
        check(victim.connect("127.0.0.1", proxy.port(), &err), "a client connects through the proxy");
        victim.request_name("short");
        check(log.wait_event("registered:short"), "it registers");
        proxy.truncate_to_client();
        check(log.wait_for([&] { std::lock_guard<std::mutex> l(log.mutex); return log.disconnected > 0; }),
              "a frame too short for a header ends the connection without crashing");
    }

    std::cout << "Old protocol version" << std::endl;
    check(old_version_hello_is_refused(), "a version 1 hello gets an error and the connection closes");

    std::cout << "Long recipient name" << std::endl;
    {
        // Older clients truncated an over-long @name and the server answered
        // "No such user"; a typo must not be treated as a failed send.
        Recorder erin_log;
        ChatClient erin(erin_log.make_events());
        std::string err;
        check(erin.connect("127.0.0.1", DEFAULT_PORT, &err), "erin connects");
        erin.request_name("erin");
        check(erin_log.wait_event("registered:erin"), "erin registers");
        const std::string long_name(40, 'z');
        check(erin.send_direct(long_name, "hi"), "direct to an over-long name is sent");
        check(erin_log.wait_event("notice:No such user: " + std::string(MAX_NAME_LEN - 1, 'z')),
              "server reports the truncated name as unknown");
    }

    std::cout << "Cancelling a connect" << std::endl;
    {
        SilentServer silent;
        Recorder log;
        ChatEvents ev = log.make_events();
        ev.on_log = [&log](const std::string& line) { log.add("log:" + line); };
        ChatClient c(ev);
        std::atomic<bool> finished{false};
        bool ok = true;
        std::thread t([&] {
            std::string err;
            ok = c.connect("127.0.0.1", silent.port(), &err);
            finished = true;
        });
        // Wait until the TCP connection is up and the handshake is waiting.
        log.wait_event("log:Sent handshake init", 15000);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const auto start = std::chrono::steady_clock::now();
        c.cancel();
        while (!finished && std::chrono::steady_clock::now() - start < std::chrono::seconds(3)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        check(finished && took < 500, "cancel() ends a connect stuck in the handshake (" +
              std::to_string(took) + " ms)");
        if (t.joinable()) t.join();
        check(!ok, "a cancelled connect reports failure");
    }

    std::cout << "Handshake timeout" << std::endl;
    {
        SilentServer silent;
        Recorder log;
        ChatClient c(log.make_events());
        std::string err;
        const auto start = std::chrono::steady_clock::now();
        const bool ok = c.connect("127.0.0.1", silent.port(), &err);
        const auto took = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start).count();
        check(!ok && took <= 12, "a server that never answers fails within the timeout (" +
              std::to_string(took) + " s)");
        check(!err.empty(), "the timeout has a reason");
    }

    std::cout << "Connect failure" << std::endl;
    {
        Recorder dave_log;
        ChatClient dave(dave_log.make_events());
        std::string err;
        check(!dave.connect("127.0.0.1", 1, &err), "connect to a closed port fails");
        check(!err.empty(), "failure has a reason");
    }

    alice.disconnect();

    if (failures == 0) {
        std::cout << "All chat client tests passed" << std::endl;
        return 0;
    }
    std::cout << failures << " chat client test(s) failed" << std::endl;
    return 1;
}
