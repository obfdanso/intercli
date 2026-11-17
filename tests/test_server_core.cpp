// The server library on its own ports: start, stop, restart, busy ports.

#include "secure_server.h"
#include "chat_client.h"
#include "frame_proxy.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <memory>
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

    std::cout << "Guessing across connections" << std::endl;
    {
        // Opening new connections must not reset the count: wrong codes are
        // counted per address, and the address is then locked out for a while.
        ServerOptions locked_options;
        locked_options.port = 18093;
        locked_options.room_code = "K7P29Q";
        locked_options.max_wrong_codes_per_address = 6;
        locked_options.lockout = std::chrono::seconds(2);
        Running locked(locked_options);

        Ears a_ears;
        ChatClient a(a_ears.events_for());
        a.connect("127.0.0.1", 18093, &err);
        for (int i = 0; i < 5; ++i) a.request_name("a" + std::to_string(i), "CCCCC" + std::to_string(i));
        check(a_ears.wait_lost(15000), "the first connection is closed after five wrong codes");

        Ears b_ears;
        ChatClient b(b_ears.events_for());
        b.connect("127.0.0.1", 18093, &err);
        b.request_name("b", "DDDDDD");
        check(b_ears.wait("failed:Wrong room code", 4000), "a new connection's guess still counts");

        Ears c_ears;
        ChatClient c(c_ears.events_for());
        c.connect("127.0.0.1", 18093, &err);
        c.request_name("c", "K7P29Q");
        check(c_ears.wait("failed:Too many wrong room codes. Try again later.", 4000),
              "even the right code is refused while the address is locked out");

        std::this_thread::sleep_for(std::chrono::milliseconds(2500));
        Ears d_ears;
        ChatClient d(d_ears.events_for());
        d.connect("127.0.0.1", 18093, &err);
        d.request_name("d", "K7P29Q");
        check(d_ears.wait("registered:d"), "the lockout ends");
    }

    std::cout << "Guesses in parallel" << std::endl;
    {
        // Guesses sent at the same moment on separate connections must not
        // slip past the limit: each one is counted before its code is compared.
        ServerOptions par_options;
        par_options.port = 18094;
        par_options.room_code = "K7P29Q";
        par_options.max_wrong_codes_per_address = 4;
        par_options.lockout = std::chrono::seconds(30);
        Running par(par_options);
        std::vector<std::unique_ptr<Ears>> ears;
        std::vector<std::unique_ptr<ChatClient>> clients;
        for (int i = 0; i < 8; ++i) {
            ears.push_back(std::make_unique<Ears>());
            clients.push_back(std::make_unique<ChatClient>(ears.back()->events_for()));
            clients.back()->connect("127.0.0.1", 18094, &err);
        }
        for (int i = 0; i < 8; ++i) {
            clients[i]->request_name("p" + std::to_string(i), "EEEEE" + std::to_string(i));
        }
        int compared = 0;
        int refused = 0;
        for (auto& e : ears) {
            if (e->wait("failed:Wrong room code", 4000)) ++compared;
            else if (e->heard("failed:Too many wrong room codes. Try again later.")) ++refused;
        }
        check(compared <= 4, "no more guesses are compared than the limit (" + std::to_string(compared) + ")");
        check(compared + refused == 8, "every guess got an answer");
    }

    std::cout << "Too many half-open connections" << std::endl;
    {
        ServerOptions cap_options;
        cap_options.port = 18095;
        cap_options.room_code = "K7P29Q";
        Running cap(cap_options);
        std::vector<std::unique_ptr<ChatClient>> idle;
        std::vector<std::unique_ptr<Ears>> idle_ears;
        int connected = 0;
        for (int i = 0; i < 12; ++i) {
            idle_ears.push_back(std::make_unique<Ears>());
            idle.push_back(std::make_unique<ChatClient>(idle_ears.back()->events_for()));
            if (idle.back()->connect("127.0.0.1", 18095, &err)) ++connected;
        }
        check(connected <= 8, "at most 8 connections that haven't joined are kept per address (" +
                                  std::to_string(connected) + ")");
    }

    std::cout << "Exempting this PC when asked" << std::endl;
    {
        ServerOptions own_options;
        own_options.port = 18096;
        own_options.room_code = "K7P29Q";
        own_options.max_wrong_codes_per_address = 2;
        own_options.exempt_loopback = true;
        Running own(own_options);
        Ears w_ears;
        ChatClient w(w_ears.events_for());
        w.connect("127.0.0.1", 18096, &err);
        w.request_name("w1", "ZZZZZZ");
        w.request_name("w2", "ZZZZZY");
        w.request_name("w3", "ZZZZZX");
        check(w_ears.wait("failed:Wrong room code", 5000), "wrong codes from this PC are still refused");
        Ears host_ears2;
        ChatClient host2(host_ears2.events_for());
        host2.connect("127.0.0.1", 18096, &err);
        host2.request_name("host", "K7P29Q");
        check(host_ears2.wait("registered:host"), "the host's own app can still join on its own machine");
    }

    std::cout << "A right code never locks you out" << std::endl;
    {
        ServerOptions ok_options;
        ok_options.port = 18098;
        ok_options.room_code = "K7P29Q";
        ok_options.max_wrong_codes_per_address = 3;
        Running ok_server(ok_options);
        Ears t_ears;
        ChatClient typo(t_ears.events_for());
        typo.connect("127.0.0.1", 18098, &err);
        typo.request_name("t1", "K7P29X");
        typo.request_name("t2", "K7P29Y");
        typo.request_name("t3", "K7P29Q");
        check(t_ears.wait("registered:t3", 8000), "two typos then the right code joins");
        typo.disconnect();
        Ears again_ears;
        ChatClient again(again_ears.events_for());
        again.connect("127.0.0.1", 18098, &err);
        again.request_name("t4", "K7P29Q");
        check(again_ears.wait("registered:t4"), "joining again right after is not locked out");
    }

    std::cout << "Stopping with a joiner that stopped reading" << std::endl;
    {
        // A relay to someone who never reads blocks in send(); stopping the
        // server (the host ending the chat) must not wait for it forever.
        ServerOptions slow_options;
        slow_options.port = 18097;
        auto slow = std::make_unique<Running>(slow_options);
        Ears a_ears;
        ChatClient a(a_ears.events_for());
        a.connect("127.0.0.1", 18097, &err);
        a.request_name("talker");
        check(a_ears.wait("registered:talker"), "a talker joins");
        FrameProxy proxy(18097);
        Ears b_ears;
        ChatClient b(b_ears.events_for());
        b.connect("127.0.0.1", proxy.port(), &err);
        b.request_name("sleeper");
        check(b_ears.wait("registered:sleeper"), "a sleeper joins through the proxy");
        proxy.stall_to_client();
        std::atomic<bool> flooding{true};
        std::thread flood([&] {
            const std::string text(1000, 'x');
            for (int i = 0; i < 3000 && flooding; ++i) {
                if (!a.send_broadcast(text)) break;
            }
        });
        std::this_thread::sleep_for(std::chrono::seconds(3));
        const auto t = std::chrono::steady_clock::now();
        slow->server.stop();
        const long long took = ms_since(t);
        check(took < 3000, "stop returns with a stalled joiner (" + std::to_string(took) + " ms)");
        flooding = false;
        a.disconnect();
        flood.join();
        slow.reset();
    }

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

// A client that records what it hears and whether it lost the connection.
static ChatEvents listen(Ears& ears) {
    ChatEvents ev;
    ev.on_registered = [&ears](const std::string& n) { ears.add("registered:" + n); };
    ev.on_register_failed = [&ears](const std::string& r) { ears.add("refused:" + r); };
    ev.on_notice = [&ears](const std::string& t) { ears.add("notice:" + t); };
    ev.on_room_message = [&ears](const std::string& room, const std::string& from, const std::string& t) {
        ears.add("room:" + room + ":" + from + ":" + t);
    };
    ev.on_room_event = [&ears](const std::string& room, const std::string& n, bool joined) {
        ears.add("roomevent:" + room + ":" + n + (joined ? ":joined" : ":left"));
    };
    ev.on_file = [&ears](const std::string& from, FileTarget target, const std::string& room,
                         const std::string& name, const std::vector<uint8_t>& data) {
        unsigned long sum = 0;
        for (uint8_t byte : data) sum += byte;
        const char kind = target == FileTarget::Direct ? 'd' : target == FileTarget::Room ? 'r' : 'e';
        ears.add(std::string("file:") + from + ":" + kind + ":" + room + ":" + name + ":" +
                 std::to_string(data.size()) + ":" + std::to_string(sum));
    };
    ev.on_direct = [&ears](const std::string& from, const std::string& t) { ears.add("direct:" + from + ":" + t); };
    ev.on_receipt = [&ears](const std::string& peer, const std::string& what) {
        ears.add("receipt:" + peer + ":" + what);
    };
    ev.on_room_list = [&ears](const std::vector<std::string>& rooms) {
        std::string all;
        for (const auto& r : rooms) all += (all.empty() ? "" : ",") + r;
        ears.add("rooms:" + all);
    };
    ev.on_presence = [&ears](const std::string& n, bool joined, const std::string&) {
        ears.add("presence:" + n + (joined ? ":joined" : ":left"));
    };
    ev.on_peer_key = [&ears](const std::string& n, bool changed) {
        ears.add("key:" + n + (changed ? ":changed" : ":fine"));
    };
    ev.on_disconnected = [&ears](const std::string&) {
        { std::lock_guard<std::mutex> lock(ears.m); ears.lost = true; }
        ears.cv.notify_all();
    };
    return ev;
}

static void host_control_tests() {
    ServerOptions options;
    options.port = 18130;
    options.room_code = "ABC234";
    Running hosted(options);
    check(hosted.ok, "a server with a room code starts");

    Ears host_ears, guest_ears;
    ChatClient host(listen(host_ears)), guest(listen(guest_ears));
    std::string error;
    check(host.connect("127.0.0.1", 18130, &error) && guest.connect("127.0.0.1", 18130, &error), "two clients connect");
    host.request_name("host", "ABC234");
    guest.request_name("guest", "ABC234");
    check(host_ears.wait("registered:host") && guest_ears.wait("registered:guest"), "both join");

    check(!hosted.server.kick("nobody"), "kicking an unknown name does nothing");
    check(hosted.server.kick("guest"), "kicking a member succeeds");
    check(guest_ears.wait("notice:The host removed you from this chat"), "the kicked person is told why");
    check(guest_ears.wait_lost(5000), "the kicked person is disconnected");
    check(host_ears.wait("presence:guest:left"), "the others see them leave");

    // A kicked person may come back; a banned one may not.
    Ears back_ears;
    ChatClient back(listen(back_ears));
    check(back.connect("127.0.0.1", 18130, &error), "the kicked person reconnects");
    back.request_name("guest", "ABC234");
    check(back_ears.wait("registered:guest"), "and joins again");
    check(hosted.server.ban("guest"), "banning a member succeeds");
    check(back_ears.wait("notice:The host banned you from this chat"), "the banned person is told why");
    check(back_ears.wait_lost(5000), "the banned person is disconnected");

    Ears again_ears;
    ChatClient again(listen(again_ears));
    check(again.connect("127.0.0.1", 18130, &error), "the banned person reconnects");
    again.request_name("guest", "ABC234");
    check(again_ears.wait("refused:The host banned you from this chat"), "but the name is refused");

    check(!hosted.server.set_room_code(""), "an empty room code is refused");
    check(hosted.server.set_room_code("xyz-789"), "the room code can be changed");
    Ears late_ears;
    ChatClient late(listen(late_ears));
    check(late.connect("127.0.0.1", 18130, &error), "a newcomer connects");
    late.request_name("late", "ABC234");
    check(late_ears.wait("refused:Wrong room code"), "the old code no longer works");
    late.request_name("late", "XYZ789");
    check(late_ears.wait("registered:late"), "the new code does");
    check(host.connected(), "people already in the chat stay");

    ServerOptions open_options;
    open_options.port = 18131;
    Running open_server(open_options);
    check(!open_server.server.set_room_code("ABC234"), "an open server cannot gain a room code while running");
}

static void room_tests() {
    ServerOptions options;
    options.port = 18132;
    Running server(options);
    check(server.ok, "a server starts");

    Ears a_ears, b_ears, c_ears;
    ChatClient a(listen(a_ears)), b(listen(b_ears)), c(listen(c_ears));
    std::string error;
    check(a.connect("127.0.0.1", 18132, &error) && b.connect("127.0.0.1", 18132, &error) &&
          c.connect("127.0.0.1", 18132, &error), "three clients connect");
    a.request_name("#ann");
    check(a_ears.wait("refused:Name must be 1-31 printable characters with no spaces, not starting with #"),
          "a name starting with # is refused");
    a.request_name("ann");
    b.request_name("ben");
    c.request_name("cat");
    check(a_ears.wait("registered:ann") && b_ears.wait("registered:ben") && c_ears.wait("registered:cat"),
          "all three join the chat");

    check(a.join_room("dev"), "joining a room is sent");
    check(a_ears.wait("roomevent:dev:ann:joined"), "the first to join creates the room and is told");
    b.join_room("dev");
    check(a_ears.wait("roomevent:dev:ben:joined") && b_ears.wait("roomevent:dev:ben:joined"),
          "members and the joiner hear a join");

    a.send_room("dev", "hello room");
    check(b_ears.wait("room:dev:ann:hello room"), "a member gets a room message");
    c.send_room("dev", "let me in");
    check(c_ears.wait("notice:You are not in the room dev"), "someone outside the room can't post to it");
    check(!c_ears.heard("room:dev:ann:hello room") && !b_ears.heard("room:dev:cat:let me in"),
          "and neither hears nor is heard");
    check(!a_ears.heard("room:dev:ann:hello room"), "the sender gets no copy");

    c.request_rooms();
    check(c_ears.wait("rooms:dev"), "the rooms can be listed");
    check(!a.join_room("#bad") && !a.join_room("two words"), "bad room names are not sent");

    b.leave_room("dev");
    check(a_ears.wait("roomevent:dev:ben:left") && b_ears.wait("roomevent:dev:ben:left"),
          "members and the leaver hear a leave");
    b.send_room("dev", "still here?");
    check(b_ears.wait("notice:You are not in the room dev"), "after leaving, posting is refused");

    // Someone who disconnects leaves their rooms.
    c.join_room("dev");
    check(a_ears.wait("roomevent:dev:cat:joined"), "a third person joins");
    c.disconnect();
    check(a_ears.wait("roomevent:dev:cat:left"), "disconnecting leaves the room");

    // A room is gone once it is empty.
    a.leave_room("dev");
    check(a_ears.wait("roomevent:dev:ann:left"), "the last member leaves");
    b.request_rooms();
    check(b_ears.wait("rooms:"), "an empty room no longer exists");
}

static void file_tests() {
    ServerOptions options;
    options.port = 18133;
    Running server(options);
    check(server.ok, "a server starts");

    Ears a_ears, b_ears, c_ears;
    ChatClient a(listen(a_ears)), b(listen(b_ears)), c(listen(c_ears));
    std::string error;
    check(a.connect("127.0.0.1", 18133, &error) && b.connect("127.0.0.1", 18133, &error) &&
          c.connect("127.0.0.1", 18133, &error), "three clients connect");
    a.request_name("ann");
    b.request_name("ben");
    c.request_name("cat");
    check(a_ears.wait("registered:ann") && b_ears.wait("registered:ben") && c_ears.wait("registered:cat"),
          "all three join the chat");

    // Big enough for many pieces and several key rotations.
    std::vector<uint8_t> photo(50000);
    unsigned long sum = 0;
    for (size_t i = 0; i < photo.size(); ++i) {
        photo[i] = static_cast<uint8_t>((i * 7) % 251);
        sum += photo[i];
    }
    const std::string tail = ":photo.png:50000:" + std::to_string(sum);

    check(a.send_file(FileTarget::Direct, "ben", "photo.png", photo), "a file is sent to one person");
    check(b_ears.wait("file:ann:d:" + tail), "it arrives whole");

    check(a.send_file(FileTarget::Everyone, "", "empty.txt", {}), "an empty file is sent to everyone");
    check(b_ears.wait("file:ann:e::empty.txt:0:0") && c_ears.wait("file:ann:e::empty.txt:0:0"),
          "everyone else gets it");
    check(!c_ears.heard("file:ann:d:" + tail), "a direct file reaches nobody else");

    a.join_room("dev");
    b.join_room("dev");
    check(a_ears.wait("roomevent:dev:ben:joined"), "two people share a room");
    check(a.send_file(FileTarget::Room, "dev", "photo.png", photo), "a file is sent to a room");
    check(b_ears.wait("file:ann:r:dev" + tail), "a member gets it, marked with the room");
    c.send_file(FileTarget::Room, "dev", "sneak.txt", {1, 2, 3});
    check(c_ears.wait("notice:You are not in the room dev"), "a file to a room you are not in is refused");
    check(!a.send_file(FileTarget::Direct, "zed", "lost.txt", std::vector<uint8_t>(3000, 1)),
          "a file to nobody is not sent");
    check(!c_ears.heard("file:ann:r:dev" + tail) && !b_ears.heard("file:cat:r:dev:sneak.txt:3:6"),
          "room files stay in the room");

    check(!a.send_file(FileTarget::Direct, "ben", "huge.bin", std::vector<uint8_t>(MAX_FILE_SIZE + 1)),
          "a file over the limit is not sent");
    check(!a.send_file(FileTarget::Direct, "ben", "", {1}), "a file needs a name");

    // Messages still flow after all those pieces and rotations.
    a.send_room("dev", "still here");
    check(b_ears.wait("room:dev:ann:still here"), "the connection is fine afterwards");
}

static void receipt_tests() {
    ServerOptions options;
    options.port = 18134;
    Running server(options);
    check(server.ok, "a server starts");

    Ears a_ears, b_ears;
    ChatClient a(listen(a_ears));
    auto b = std::make_unique<ChatClient>(listen(b_ears));
    // Ben keeps his key between visits, as the real clients do.
    const auto ben_keys = std::make_shared<KeyStore>();
    b->use_key_store(ben_keys);
    std::string error;
    check(a.connect("127.0.0.1", 18134, &error) && b->connect("127.0.0.1", 18134, &error), "two clients connect");
    a.request_name("ann");
    b->request_name("ben");
    check(a_ears.wait("registered:ann") && b_ears.wait("registered:ben"), "both join");

    a.send_direct("ben", "hello");
    check(b_ears.wait("direct:ann:hello"), "a direct message arrives");
    check(a_ears.wait("receipt:ben:delivered"), "the sender is told it was delivered");
    b->send_read("ann");
    check(a_ears.wait("receipt:ben:read"), "the sender is told it was read");

    a.send_direct("ghost", "anyone?");
    check(a_ears.wait("notice:No such user: ghost"), "a name never seen is still refused");

    // Ben goes away; a message to him is kept and handed over when he is back.
    b.reset();
    check(a_ears.wait("presence:ben:left"), "ben leaves");
    a.send_direct("ben", "see this later");
    check(a_ears.wait("receipt:ben:queued"), "the sender is told it is kept for later");

    Ears back_ears;
    ChatClient back(listen(back_ears));
    back.use_key_store(ben_keys);
    check(back.connect("127.0.0.1", 18134, &error), "ben reconnects");
    back.request_name("ben");
    check(back_ears.wait("registered:ben"), "and joins again");
    check(back_ears.wait("notice:1 message arrived while you were away"), "he is told something was kept");
    check(back_ears.wait("direct:ann:see this later"), "and gets it");

    // Kept once, delivered once.
    Ears third_ears;
    back.disconnect();
    check(a_ears.wait("presence:ben:left"), "ben leaves again");
    ChatClient third(listen(third_ears));
    third.use_key_store(ben_keys);
    check(third.connect("127.0.0.1", 18134, &error), "ben reconnects once more");
    third.request_name("ben");
    check(third_ears.wait("registered:ben"), "and joins");
    a.send_direct("ben", "marker");
    check(third_ears.wait("direct:ann:marker"), "new messages arrive");
    check(!third_ears.heard("direct:ann:see this later"), "the kept message is not delivered twice");
}

// Direct messages are sealed between the two people: the server only passes
// them on, and someone who takes over a name cannot read what was meant for
// the person before.
static void end_to_end_tests() {
    ServerOptions options;
    options.port = 18135;
    Running server(options);
    check(server.ok, "a server starts");

    Ears a_ears, b_ears, c_ears;
    ChatClient a(listen(a_ears)), c(listen(c_ears));
    auto b = std::make_unique<ChatClient>(listen(b_ears));
    std::string error;
    check(a.connect("127.0.0.1", 18135, &error) && b->connect("127.0.0.1", 18135, &error) &&
          c.connect("127.0.0.1", 18135, &error), "three clients connect");
    a.request_name("ann");
    b->request_name("ben");
    c.request_name("cat");
    check(a_ears.wait("registered:ann") && b_ears.wait("registered:ben") && c_ears.wait("registered:cat"),
          "all three join");

    check(a.safety_code_with("ben").empty(), "there is no safety code before a key is known");
    check(a.send_direct("ben", "secret"), "a direct message is accepted");
    check(b_ears.wait("direct:ann:secret"), "it arrives readable");
    check(a_ears.wait("key:ben:fine") && b_ears.wait("key:ann:fine"), "each learns the other's key");
    check(a.safety_code_with("ben").size() == 71 && a.safety_code_with("ben") == b->safety_code_with("ann"),
          "both see the same safety code");
    b->send_direct("ann", "reply");
    check(a_ears.wait("direct:ben:reply"), "and the answer comes back");

    check(a.request_key("cat") && a_ears.wait("key:cat:fine"), "a key can be asked for ahead of time");
    check(!a.safety_code_with("cat").empty() && a.safety_code_with("cat") != a.safety_code_with("ben"),
          "every pair has its own safety code");

    // Many at once, before the key is known: all arrive, in the order written.
    for (int i = 0; i < 20; ++i) {
        c.send_direct("ben", "n" + std::to_string(i));
    }
    check(b_ears.wait("direct:cat:n19"), "messages written before the key arrived are sent");
    {
        std::lock_guard<std::mutex> lock(b_ears.m);
        int next = 0;
        for (const auto& e : b_ears.events) {
            if (e == "direct:cat:n" + std::to_string(next)) ++next;
        }
        check(next == 20, "in the order they were written");
    }

    check(a.send_direct("ben", std::string(MAX_DIRECT_TEXT, 'x')), "the longest direct message is accepted");
    check(b_ears.wait("direct:ann:" + std::string(MAX_DIRECT_TEXT, 'x')), "and arrives whole");
    check(!a.send_direct("ben", std::string(MAX_DIRECT_TEXT + 1, 'x')), "one byte more is refused");

    // Ben leaves. What ann writes meanwhile is sealed for ben's key, so
    // someone else who takes the name gets it handed over but cannot read it.
    b.reset();
    check(a_ears.wait("presence:ben:left"), "ben leaves");
    a.send_direct("ben", "for ben only");
    check(a_ears.wait("receipt:ben:queued"), "a message for him is kept");

    Ears eve_ears;
    ChatClient eve(listen(eve_ears));
    check(eve.connect("127.0.0.1", 18135, &error), "someone else connects");
    eve.request_name("ben");
    check(eve_ears.wait("registered:ben"), "and takes ben's name");
    check(eve_ears.wait("notice:A private message from ann could not be read"),
          "the kept message cannot be read with another key");
    check(!eve_ears.heard("direct:ann:for ben only"), "so it is never shown");

    a.send_direct("ben", "who are you");
    check(a_ears.wait("key:ben:changed"), "the sender is warned that ben's key is different");
    check(eve_ears.wait("direct:ann:who are you"), "messages written after that go to the new holder");
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

    std::cout << "Host controls" << std::endl;
    host_control_tests();

    std::cout << "Named rooms" << std::endl;
    room_tests();

    std::cout << "Files" << std::endl;
    file_tests();

    std::cout << "Away messages and receipts" << std::endl;
    receipt_tests();
    end_to_end_tests();

    if (failures == 0) {
        std::cout << "All server core tests passed" << std::endl;
        return 0;
    }
    std::cout << failures << " server core test(s) failed" << std::endl;
    return 1;
}
