#include "secure_server.h"
#include "../../crypto/crypto_utils.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <poll.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <cerrno>
#endif

namespace SecureComm {

namespace {

#ifdef _WIN32
using socket_t = SOCKET;
#else
using socket_t = int;
#endif

} // namespace

// Collects one log line and hands it to the log callback when the statement ends.
class LogLine {
public:
    LogLine(SecureServer::Impl* server, bool is_error) : server_(server), is_error_(is_error) {}
    ~LogLine();
    template <typename T>
    LogLine& operator<<(const T& value) {
        out_ << value;
        return *this;
    }

private:
    SecureServer::Impl* server_;
    bool is_error_;
    std::ostringstream out_;
};

static void close_socket(intptr_t s) {
#ifdef _WIN32
    closesocket(static_cast<SOCKET>(s));
#else
    close(static_cast<int>(s));
#endif
}

// Linux raises SIGPIPE on a send to a closed socket, which would end the whole
// process (the desktop app too, when it hosts); ask for an error instead.
#ifdef MSG_NOSIGNAL
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;
#endif

// A connection gets this long to finish the handshake, so one that connects
// and then says nothing cannot hold a thread for ever.
constexpr std::chrono::seconds kHandshakeTimeout(10);

// One thread serves every connection, so nothing in it may wait on one client.
// Output a client is slow to take is queued; these bound the queues:
// stop reading new input while this much output is waiting in total,
constexpr size_t kPauseReadingAbove = 4 * 1024 * 1024;
// never queue more than this for one client,
constexpr size_t kMaxQueuedOutput = 16 * 1024 * 1024;
// and give up on a client that has taken nothing for this long.
constexpr std::chrono::seconds kOutputStall(5);
// A client with more than this waiting must also keep taking it at a real
// rate (this much every kOutputStall), or it is dropped: reading a byte now
// and then must not let one client hold up everyone else.
constexpr size_t kSlowClientMark = 256 * 1024;
constexpr int kLoopTickMs = 50;

static void set_nonblocking(intptr_t s) {
#ifdef _WIN32
    u_long on = 1;
    ioctlsocket(static_cast<SOCKET>(s), FIONBIO, &on);
#else
    fcntl(static_cast<int>(s), F_SETFL, fcntl(static_cast<int>(s), F_GETFL, 0) | O_NONBLOCK);
#endif
}

// Whether the last send or recv failed only because it would have had to wait.
static bool would_block() {
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

// One connected client. Held by shared_ptr because a relaying thread may be
// mid-send to a client that is disconnecting; the object outlives the registry
// entry until the last reference drops, and alive makes late sends no-ops.
struct ClientConnection {
    intptr_t          socket = -1;
    uint32_t          session_id = 0;
    std::string       name;
    std::mutex        send_mutex;
    uint32_t          sent_count = 0;  // guarded by send_mutex
    uint32_t          tx_seq = 0;      // last frame number sent; guarded by send_mutex
    uint32_t          rx_seq = 0;      // last frame number received; receive thread only
    int               wrong_codes = 0; // wrong room codes tried; receive thread only
    std::string       address;         // what guesses are counted against: the IP
                                       // address, or the /64 network for IPv6
    std::string       peer;            // the client's exact IP address, for bans
    std::string       e2e_key;         // the person's public key for end-to-end encryption, if given
    bool              counted_joined = false;  // released from the pending count
    std::atomic<bool> alive{true};         // false: the loop closes it on its next pass

    // The event loop's own state; touched only by the loop thread, except out
    // and out_progress, which send_mutex guards.
    enum class Stage { Hello, Confirm, Chat };
    Stage             stage = Stage::Hello;
    SessionInfo       session;
    uint32_t          client_id = 0;
    std::vector<uint8_t> in;               // bytes received, not yet a whole frame
    std::vector<uint8_t> out;              // frames waiting for the socket to take them
    std::chrono::steady_clock::time_point out_progress{};  // when out last shrank
    std::chrono::steady_clock::time_point out_window{};    // start of the current rate check, if one is on
    size_t            out_window_sent = 0;                 // bytes the client took since then
    std::chrono::steady_clock::time_point deadline{};      // the handshake must be done by then
    std::chrono::steady_clock::time_point paused_until{};  // input is not looked at before then
};

// using namespace SecureComm; // Removed to avoid namespace conflicts

struct SecureServer::Impl {
    ServerOptions options_;
    std::atomic<intptr_t> server_socket_;
    std::atomic<bool> running_;
    std::unique_ptr<CryptoManager> crypto_manager_;
    std::unique_ptr<SessionManager> session_manager_;
    std::unique_ptr<KeyManager> key_manager_;
    // Every live connection, registered or not, so stop() can wait for their
    // threads. A thread removes its own entry as the last thing it does.
    std::set<std::shared_ptr<ClientConnection>> connections_;
    std::mutex connections_mutex_;
    std::condition_variable connections_cv_;
    bool loop_active_ = false;  // run() is serving; guarded by connections_mutex_
    std::map<std::string, std::shared_ptr<ClientConnection>> registry_;
    std::mutex registry_mutex_;

    // Room code guesses per address, across connections, so guessing can't be
    // sped up by opening more connections.
    struct Guesses {
        int count = 0;
        int lockouts = 0;
        int pending = 0;  // connections from this address that haven't joined yet
        std::chrono::steady_clock::time_point locked_until{};
        std::chrono::steady_clock::time_point last_seen{};
    };
    std::map<std::string, Guesses> guesses_;
    std::mutex guesses_mutex_;
    static constexpr size_t kMaxTrackedAddresses = 4096;
    static constexpr int kMaxPendingPerAddress = 8;

    bool exempt(const std::string& address) const {
        return options_.exempt_loopback && (address.rfind("127.", 0) == 0 || address == "::1");
    }

    // Forgets addresses that are neither locked out nor recently active, and
    // keeps the table bounded. Caller holds guesses_mutex_.
    void prune_guesses(std::chrono::steady_clock::time_point now) {
        for (auto it = guesses_.begin(); it != guesses_.end();) {
            const Guesses& g = it->second;
            const bool idle = g.pending == 0 && now >= g.locked_until && now - g.last_seen > std::chrono::hours(1);
            it = idle ? guesses_.erase(it) : std::next(it);
        }
        while (guesses_.size() > kMaxTrackedAddresses) {
            auto oldest = guesses_.end();
            for (auto it = guesses_.begin(); it != guesses_.end(); ++it) {
                if (it->second.pending == 0 && now >= it->second.locked_until &&
                    (oldest == guesses_.end() || it->second.last_seen < oldest->second.last_seen)) {
                    oldest = it;
                }
            }
            if (oldest == guesses_.end()) {
                break;
            }
            guesses_.erase(oldest);
        }
    }

    // A new connection that still has to join. False: too many from this address.
    bool admit_pending(const std::string& address) {
        if (options_.room_code.empty() || exempt(address)) {
            return true;
        }
        std::lock_guard<std::mutex> lock(guesses_mutex_);
        const auto now = std::chrono::steady_clock::now();
        prune_guesses(now);
        Guesses& g = guesses_[address];
        g.last_seen = now;
        if (g.pending >= kMaxPendingPerAddress) {
            return false;
        }
        ++g.pending;
        return true;
    }

    // The connection joined or went away.
    void release_pending(const std::string& address) {
        if (options_.room_code.empty() || exempt(address)) {
            return;
        }
        std::lock_guard<std::mutex> lock(guesses_mutex_);
        auto it = guesses_.find(address);
        if (it != guesses_.end() && it->second.pending > 0) {
            --it->second.pending;
        }
    }

    // Checks the lockout and counts the guess in one step, before the code is
    // compared, so guesses sent at once on several connections can't slip past
    // the limit. False: locked out or out of guesses, don't compare.
    bool begin_guess(const std::string& address) {
        if (exempt(address)) {
            return true;
        }
        std::lock_guard<std::mutex> lock(guesses_mutex_);
        const auto now = std::chrono::steady_clock::now();
        Guesses& g = guesses_[address];
        g.last_seen = now;
        if (now < g.locked_until || g.count >= options_.max_wrong_codes_per_address) {
            return false;
        }
        ++g.count;
        return true;
    }

    // The guess was wrong. Once the address has used up its guesses it is
    // locked out; each lockout lasts twice as long as the one before, up to an
    // hour. (A right guess never locks anyone out.)
    void guess_failed(const std::string& address) {
        if (exempt(address)) {
            return;
        }
        std::lock_guard<std::mutex> lock(guesses_mutex_);
        Guesses& g = guesses_[address];
        if (g.count >= options_.max_wrong_codes_per_address) {
            const auto now = std::chrono::steady_clock::now();
            const auto factor = 1LL << (std::min)(g.lockouts, 6);
            const auto length = (std::min<std::chrono::seconds>)(options_.lockout * factor, std::chrono::hours(1));
            g.locked_until = now + length;
            g.count = 0;
            ++g.lockouts;
            LogLine(this, false) << "Locked out " << address << " for " << length.count()
                                 << " s after too many wrong room codes";
        }
    }

    // A right code: that guess doesn't count against the address.
    void guess_succeeded(const std::string& address) {
        if (exempt(address)) {
            return;
        }
        std::lock_guard<std::mutex> lock(guesses_mutex_);
        auto it = guesses_.find(address);
        if (it != guesses_.end()) {
            it->second.count = 0;
        }
    }

    // Constant time, so how long the comparison takes says nothing about the code.
    mutable std::mutex room_code_mutex_;

    // Whether there is a code never changes while running (the per-address
    // counts depend on it), so only the code itself needs the lock.
    bool set_room_code(const std::string& typed) {
        const std::string code = normalize_room_code(typed);
        if (code.empty() || code.size() >= MAX_NAME_LEN) {
            return false;
        }
        std::lock_guard<std::mutex> lock(room_code_mutex_);
        if (options_.room_code.empty()) {
            return false;
        }
        options_.room_code = code;
        LogLine(this, false) << "The host changed the room code";
        return true;
    }

    bool room_code_matches(const std::string& typed) const {
        const std::string candidate = normalize_room_code(typed);
        std::string code;
        {
            // The host can change the code while people are joining.
            std::lock_guard<std::mutex> lock(room_code_mutex_);
            code = options_.room_code;
        }
        if (candidate.size() != code.size()) {
            return false;
        }
        return CRYPTO_memcmp(candidate.data(), code.data(), code.size()) == 0;
    }
    IdentityKey identity_;

    explicit Impl(ServerOptions options)
        : options_(std::move(options)), server_socket_(-1), running_(false) {
        banned_names_.insert(options_.banned_names.begin(), options_.banned_names.end());
        banned_addresses_.insert(options_.banned_addresses.begin(), options_.banned_addresses.end());
#ifdef _WIN32
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif

        crypto_manager_ = std::make_unique<CryptoManager>();
        session_manager_ = std::make_unique<SessionManager>();
        key_manager_ = std::make_unique<KeyManager>();
        
        options_.room_code = normalize_room_code(options_.room_code);

        // The long-term identity the server signs every handshake with.
        identity_ = options_.identity_private.size() == 32
            ? crypto_manager_->identity_from_private(options_.identity_private)
            : crypto_manager_->generate_identity();
    }

    ~Impl() {
        stop();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    bool start(std::string* error) {
        const uint16_t port = options_.port;
        auto fail = [&](const std::string& reason) {
            LogLine(this, true) << reason;
            if (error) {
                *error = reason;
            }
            const intptr_t listener = server_socket_.exchange(-1);
            if (listener >= 0) {
                close_socket(listener);
            }
            return false;
        };

        // One socket for both kinds of address: an IPv6 socket with V6ONLY off
        // also takes IPv4 connections. Where IPv6 is switched off, IPv4 alone.
        bool dual_stack = true;
        server_socket_ = static_cast<intptr_t>(socket(AF_INET6, SOCK_STREAM, 0));
        if (server_socket_ >= 0) {
            int v6_only = 0;
            if (setsockopt(static_cast<socket_t>(server_socket_), IPPROTO_IPV6, IPV6_V6ONLY,
                           reinterpret_cast<const char*>(&v6_only), sizeof(v6_only)) < 0) {
                close_socket(server_socket_.exchange(-1));
            }
        }
        if (server_socket_ < 0) {
            dual_stack = false;
            server_socket_ = static_cast<intptr_t>(socket(AF_INET, SOCK_STREAM, 0));
        }
        if (server_socket_ < 0) {
            return fail("Failed to create socket");
        }

        int opt = 1;
#ifdef _WIN32
        // Exclusive: on Windows SO_REUSEADDR would let a second server bind a port
        // that is already in use without any error.
        const int option = SO_EXCLUSIVEADDRUSE;
#else
        const int option = SO_REUSEADDR;
#endif
        if (setsockopt(static_cast<socket_t>(server_socket_), SOL_SOCKET, option,
                       reinterpret_cast<const char*>(&opt), sizeof(opt)) < 0) {
            return fail("Failed to set socket options");
        }

        struct sockaddr_in6 addr6 {};
        addr6.sin6_family = AF_INET6;
        addr6.sin6_addr = in6addr_any;
        addr6.sin6_port = htons(port);
        struct sockaddr_in addr4 {};
        addr4.sin_family = AF_INET;
        addr4.sin_addr.s_addr = INADDR_ANY;
        addr4.sin_port = htons(port);
        const struct sockaddr* server_addr = dual_stack ? reinterpret_cast<const struct sockaddr*>(&addr6)
                                                        : reinterpret_cast<const struct sockaddr*>(&addr4);
        const socklen_t server_addr_len = dual_stack ? sizeof(addr6) : sizeof(addr4);

        if (bind(static_cast<socket_t>(server_socket_), server_addr, server_addr_len) < 0) {
            return fail("Port " + std::to_string(port) + " is already in use");
        }

        if (listen(static_cast<socket_t>(server_socket_), 10) < 0) {
            return fail("Failed to listen on socket");
        }

        running_ = true;
        LogLine(this, false) << "Secure server started on port " << port;
        LogLine(this, false) << "Server safety code: " << safety_code(identity_.public_raw);

        // Sessions are removed when their connection ends. (Expiring them by
        // age cut off every client that had been connected for a day.)

        return true;
    }

    // Takes one waiting connection, if it may come in, and sets it up for the loop.
    void accept_one() {
        struct sockaddr_storage client_addr {};
        socklen_t client_len = sizeof(client_addr);

        intptr_t client_socket = static_cast<intptr_t>(accept(static_cast<socket_t>(server_socket_), (struct sockaddr*)&client_addr, &client_len));
        if (client_socket < 0) {
            if (running_) {
                LogLine(this, true) << "Failed to accept client connection";
                // Out of descriptors, say: don't spin on the same failure.
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            return;
        }

        // An IPv4 client on the shared socket arrives as ::ffff:a.b.c.d; it
        // is named a.b.c.d, so one machine is one address for the lockouts.
        char addr_text[INET6_ADDRSTRLEN + 4] = "?";
        char exact_text[INET6_ADDRSTRLEN] = "";  // set only where it differs
        uint16_t client_port = 0;
        if (client_addr.ss_family == AF_INET6) {
            const auto* a = reinterpret_cast<const struct sockaddr_in6*>(&client_addr);
            client_port = ntohs(a->sin6_port);
            if (IN6_IS_ADDR_V4MAPPED(&a->sin6_addr)) {
                inet_ntop(AF_INET, a->sin6_addr.s6_addr + 12, addr_text, sizeof(addr_text));
            } else if (IN6_IS_ADDR_LOOPBACK(&a->sin6_addr)) {
                inet_ntop(AF_INET6, &a->sin6_addr, addr_text, sizeof(addr_text));
            } else if (!options_.allow_global_ipv6 && !IN6_IS_ADDR_LINKLOCAL(&a->sin6_addr) &&
                       (a->sin6_addr.s6_addr[0] & 0xfe) != 0xfc) {
                LogLine(this, false) << "Refused an IPv6 connection from outside the local network";
                close_socket(client_socket);
                return;
            } else {
                // One machine can use any address in its /64 network, so the
                // network is what gets counted and locked out: changing
                // address must not buy more room code guesses.
                inet_ntop(AF_INET6, &a->sin6_addr, exact_text, sizeof(exact_text));
                struct in6_addr network = a->sin6_addr;
                std::memset(network.s6_addr + 8, 0, 8);
                inet_ntop(AF_INET6, &network, addr_text, sizeof(addr_text));
                std::strncat(addr_text, "/64", sizeof(addr_text) - std::strlen(addr_text) - 1);
            }
        } else {
            const auto* a = reinterpret_cast<const struct sockaddr_in*>(&client_addr);
            client_port = ntohs(a->sin_port);
            inet_ntop(AF_INET, &a->sin_addr, addr_text, sizeof(addr_text));
        }
        LogLine(this, false) << "New client connected from " << addr_text << " port " << client_port;

        if (!admit_pending(addr_text)) {
            // Too many connections from one address that haven't joined.
            close_socket(client_socket);
            return;
        }

        auto conn = std::make_shared<ClientConnection>();
        conn->socket = client_socket;
        conn->address = addr_text;
        conn->peer = exact_text[0] ? exact_text : addr_text;
        set_nonblocking(client_socket);
        const auto now = std::chrono::steady_clock::now();
        conn->client_id = generate_client_id();
        conn->session = session_manager_->create_session(conn->client_id);
        conn->session_id = conn->session.session_id;
        conn->deadline = now + kHandshakeTimeout;
        conn->out_progress = now;
        LogLine(this, false) << "Created session " << conn->session_id << " for client " << conn->client_id;

        std::lock_guard<std::mutex> lock(connections_mutex_);
        connections_.insert(conn);
    }

    // The event loop: one thread waits on every socket at once and does whatever
    // each is ready for. Nothing here waits on a single client: reads and writes
    // never block, and output a client is slow to take is queued.
    void run() {
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            loop_active_ = true;
        }
        std::vector<std::shared_ptr<ClientConnection>> conns;
        std::vector<pollfd> fds;
        while (running_) {
            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                conns.assign(connections_.begin(), connections_.end());
            }
            const auto now = std::chrono::steady_clock::now();

            // When clients are slow to take what is queued for them, stop
            // taking new input until it drains, so the queues stay bounded.
            size_t queued = 0;
            std::vector<bool> has_output(conns.size(), false);
            for (size_t i = 0; i < conns.size(); ++i) {
                std::lock_guard<std::mutex> lock(conns[i]->send_mutex);
                queued += conns[i]->out.size();
                has_output[i] = !conns[i]->out.empty();
            }
            const bool reading = queued < kPauseReadingAbove;

            fds.clear();
            pollfd listener{};
            listener.fd = static_cast<socket_t>(server_socket_.load());
            listener.events = POLLIN;
            fds.push_back(listener);
            for (size_t i = 0; i < conns.size(); ++i) {
                pollfd entry{};
                entry.fd = static_cast<socket_t>(conns[i]->socket);
                if (reading && now >= conns[i]->paused_until) {
                    entry.events |= POLLIN;
                }
                if (has_output[i]) {
                    entry.events |= POLLOUT;
                }
                fds.push_back(entry);
            }
#ifdef _WIN32
            const int ready = WSAPoll(fds.data(), static_cast<ULONG>(fds.size()), kLoopTickMs);
#else
            const int ready = poll(fds.data(), fds.size(), kLoopTickMs);
#endif
            if (ready < 0) {
                // Interrupted, or the listener went away under us while stopping.
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            if (fds[0].revents & POLLIN) {
                accept_one();
            }

            for (size_t i = 0; i < conns.size(); ++i) {
                const std::shared_ptr<ClientConnection>& conn = conns[i];
                const auto revents = fds[i + 1].revents;
                if (conn->alive && (revents & (POLLIN | POLLHUP | POLLERR))) {
                    read_input(conn);
                }
                if (conn->alive) {
                    process_input(conn);
                }
                bool stalled = false;
                {
                    std::lock_guard<std::mutex> lock(conn->send_mutex);
                    if (!conn->out.empty()) {
                        flush_locked(conn);
                    }
                    const auto after = std::chrono::steady_clock::now();
                    stalled = !conn->out.empty() && after - conn->out_progress > kOutputStall;
                    if (conn->out.size() <= kSlowClientMark) {
                        conn->out_window = {};  // little waiting: no rate to check
                    } else if (conn->out_window == std::chrono::steady_clock::time_point{}) {
                        conn->out_window = after;
                        conn->out_window_sent = 0;
                    } else if (after - conn->out_window > kOutputStall) {
                        stalled = stalled || conn->out_window_sent < kSlowClientMark;
                        conn->out_window = after;
                        conn->out_window_sent = 0;
                    }
                }
                if (stalled && conn->alive) {
                    LogLine(this, false) << "Dropped a client that stopped reading or reads too slowly";
                    conn->alive = false;
                }
                if (conn->alive && conn->stage != ClientConnection::Stage::Chat && now > conn->deadline) {
                    LogLine(this, true) << "Handshake failed for client " << conn->client_id;
                    conn->alive = false;
                }
                // The name is only set on this thread, so it can be read here.
                if (conn->alive && conn->stage == ClientConnection::Stage::Chat && conn->name.empty() &&
                    now > conn->deadline) {
                    LogLine(this, false) << "Dropped client " << conn->client_id << ", which never picked a name";
                    conn->alive = false;
                }
                if (!conn->alive) {
                    close_connection(conn);
                }
            }
        }

        // Stopping: every connection is closed before stop() is let go.
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            conns.assign(connections_.begin(), connections_.end());
        }
        for (const auto& conn : conns) {
            close_connection(conn);
        }
        const intptr_t listener = server_socket_.exchange(-1);
        if (listener >= 0) {
            close_socket(listener);
        }
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            loop_active_ = false;
        }
        connections_cv_.notify_all();
    }

    // Takes what the socket has, without waiting for more.
    void read_input(const std::shared_ptr<ClientConnection>& conn) {
        uint8_t buffer[65536];
        for (int round = 0; round < 4; ++round) {
            const int received = recv(static_cast<socket_t>(conn->socket), reinterpret_cast<char*>(buffer),
                                      static_cast<int>(sizeof(buffer)), 0);
            if (received > 0) {
                conn->in.insert(conn->in.end(), buffer, buffer + received);
                if (received < static_cast<int>(sizeof(buffer))) {
                    return;
                }
            } else {
                if (received == 0 || !would_block()) {
                    conn->alive = false;  // closed, or broken
                }
                return;
            }
        }
    }

    // Handles every whole frame received so far. Each frame has a 4-byte
    // big-endian length in front, so one split across packets waits here until
    // the rest arrives.
    void process_input(const std::shared_ptr<ClientConnection>& conn) {
        size_t at = 0;
        while (conn->alive && conn->in.size() - at >= 4 && std::chrono::steady_clock::now() >= conn->paused_until) {
            const uint8_t* head = conn->in.data() + at;
            const uint32_t length = (static_cast<uint32_t>(head[0]) << 24) | (static_cast<uint32_t>(head[1]) << 16) |
                                    (static_cast<uint32_t>(head[2]) << 8) | static_cast<uint32_t>(head[3]);
            if (length == 0 || length > MAX_FRAME_SIZE) {
                conn->alive = false;
                break;
            }
            if (conn->in.size() - at - 4 < length) {
                break;
            }
            const std::vector<uint8_t> frame(head + 4, head + 4 + length);
            at += 4 + static_cast<size_t>(length);
            if (!handle_frame(conn, frame)) {
                conn->alive = false;
            }
        }
        conn->in.erase(conn->in.begin(), conn->in.begin() + static_cast<std::ptrdiff_t>(at));
    }

    // One frame, according to how far the connection has got. False: close it.
    bool handle_frame(const std::shared_ptr<ClientConnection>& conn, const std::vector<uint8_t>& frame) {
        try {
            switch (conn->stage) {
                case ClientConnection::Stage::Hello:
                    if (!handshake_hello(conn, frame)) {
                        LogLine(this, true) << "Handshake failed for client " << conn->client_id;
                        return false;
                    }
                    conn->stage = ClientConnection::Stage::Confirm;
                    return true;
                case ClientConnection::Stage::Confirm:
                    if (!handshake_confirm(conn, frame)) {
                        LogLine(this, true) << "Handshake failed for client " << conn->client_id;
                        return false;
                    }
                    conn->stage = ClientConnection::Stage::Chat;
                    // From now on the deadline is for picking a name.
                    conn->deadline = std::chrono::steady_clock::now() + options_.name_timeout;
                    LogLine(this, false) << "Handshake completed successfully for client " << conn->client_id;
                    return true;
                case ClientConnection::Stage::Chat:
                    return handle_encrypted_frame(conn, frame);
            }
        } catch (const std::exception& e) {
            LogLine(this, true) << "Error handling client: " << e.what();
        }
        return false;
    }

    void stop() {
        running_ = false;
        {
            // run() notices within a tick, closes every connection and the
            // listener, and only then lets us go.
            std::unique_lock<std::mutex> lock(connections_mutex_);
            connections_cv_.wait(lock, [this] { return !loop_active_; });
        }
        // Started but never run: only the listener is open.
        const intptr_t listener = server_socket_.exchange(-1);
        if (listener >= 0) {
            close_socket(listener);
        }
    }

    size_t people() {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        return registry_.size();
    }

    std::vector<uint8_t> identity_public() const {
        return identity_.public_raw;
    }

    // Tells the person why, then cuts the connection; their own thread tidies
    // up and announces that they left.
    bool remove_person(const std::string& name, const std::string& reason) {
        std::shared_ptr<ClientConnection> conn = lookup(name);
        if (!conn) {
            return false;
        }
        send_notice(conn, reason);
        std::lock_guard<std::mutex> lock(conn->send_mutex);
        if (conn->alive) {
            drop_locked(conn);
        }
        LogLine(this, false) << "The host removed " << name;
        return true;
    }

    bool kick(const std::string& name) {
        return remove_person(name, "The host removed you from this chat");
    }

    // Names and addresses the host has banned; guarded by admin_mutex_.
    std::set<std::string> banned_names_;
    std::set<std::string> banned_addresses_;
    std::mutex admin_mutex_;

    bool ban(const std::string& name) {
        std::shared_ptr<ClientConnection> conn = lookup(name);
        if (!conn) {
            return false;
        }
        const std::string reason = "The host banned you from this chat";
        // Never this PC's own address: the host joins from it too.
        // The exact address, not the network guesses are counted against: a
        // ban must not take the person's neighbours with it.
        const bool ban_address = conn->peer.rfind("127.", 0) != 0 && conn->peer != "::1";
        {
            std::lock_guard<std::mutex> lock(admin_mutex_);
            banned_names_.insert(name);
            if (ban_address) {
                banned_addresses_.insert(conn->peer);
            }
        }
        if (ban_address) {
            // Everything else that machine has open goes too, or it would stay
            // in the chat under another name.
            std::vector<std::shared_ptr<ClientConnection>> same_machine;
            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                for (const auto& other : connections_) {
                    if (other != conn && other->peer == conn->peer) {
                        same_machine.push_back(other);
                    }
                }
            }
            for (const auto& other : same_machine) {
                // Only a joined connection has keys set up for a notice.
                bool joined = false;
                {
                    // The name is written under this lock when someone joins.
                    std::lock_guard<std::mutex> lock(registry_mutex_);
                    joined = !other->name.empty();
                }
                if (joined) {
                    send_notice(other, reason);
                }
                std::lock_guard<std::mutex> lock(other->send_mutex);
                if (other->alive) {
                    drop_locked(other);
                }
            }
        }
        return remove_person(name, reason);
    }

    SecureServer::Bans bans() {
        std::lock_guard<std::mutex> lock(admin_mutex_);
        return {std::vector<std::string>(banned_names_.begin(), banned_names_.end()),
                std::vector<std::string>(banned_addresses_.begin(), banned_addresses_.end())};
    }

    void clear_bans() {
        std::lock_guard<std::mutex> lock(admin_mutex_);
        banned_names_.clear();
        banned_addresses_.clear();
    }

    bool banned_name(const std::string& name) {
        std::lock_guard<std::mutex> lock(admin_mutex_);
        return banned_names_.count(name) > 0;
    }

    bool banned_address(const std::string& address) {
        std::lock_guard<std::mutex> lock(admin_mutex_);
        return banned_addresses_.count(address) > 0;
    }

    // Everything that ends a connection: it leaves its rooms, its name is freed
    // and the others are told, then the socket is closed. Loop thread only.
    void close_connection(const std::shared_ptr<ClientConnection>& conn) {
        conn->alive = false;
        if (!conn->counted_joined) {
            release_pending(conn->address);
        }
        const std::string departed = conn->name;
        if (!departed.empty()) {
            for (const std::string& room : leave_all_rooms(conn)) {
                send_room_event(room, departed, false, nullptr);
            }
        }
        unregister(conn);
        if (!departed.empty()) {
            broadcast_presence(departed, false, std::string());
        }
        if (conn->session_id != 0) {
            session_manager_->remove_session(conn->session_id);
        }
        LogLine(this, false) << "Client disconnected";
        {
            // Under send_mutex, so another thread (the host removing someone)
            // can't be writing to the socket as it closes. What is already
            // queued, such as the reason for a refusal, gets one last try.
            std::lock_guard<std::mutex> send_lock(conn->send_mutex);
            flush_locked(conn);
            close_socket(conn->socket);
            conn->socket = -1;
        }
        std::lock_guard<std::mutex> lock(connections_mutex_);
        connections_.erase(conn);
    }

    // Sends a header-only error frame on a socket not yet tied to a connection.
    void send_raw_error(const std::shared_ptr<ClientConnection>& conn, ErrorCode code) {
        MessageHeader header{};
        header.version = PROTOCOL_VERSION;
        header.type = MessageType::ERROR_MESSAGE;
        header.timestamp = get_current_timestamp_seconds();
        header.payload_size = sizeof(ErrorCode);
        std::vector<uint8_t> frame = serialize_header(header);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&code);
        frame.insert(frame.end(), p, p + sizeof(ErrorCode));
        std::lock_guard<std::mutex> lock(conn->send_mutex);
        send_data(conn, frame);
    }

    // Steps 1 to 3, on the client's hello: check it, make our keys and answer.
    bool handshake_hello(const std::shared_ptr<ClientConnection>& conn, const std::vector<uint8_t>& handshake_data) {
        SessionInfo& session = conn->session;
        try {
            // Step 1: the client's hello.
            if (handshake_data.size() < sizeof(MessageHeader) + sizeof(HandshakeMessage)) {
                LogLine(this, true) << "Handshake message too short";
                return false;
            }
            MessageHeader header = deserialize_header(handshake_data);
            if (header.type != MessageType::HANDSHAKE_INIT) {
                LogLine(this, true) << "Expected HANDSHAKE_INIT, got " << message_type_to_string(header.type);
                return false;
            }
            if (header.version != PROTOCOL_VERSION) {
                // An older client: tell it so instead of half-working.
                LogLine(this, false) << "Refused a client using an older protocol version";
                send_raw_error(conn, ErrorCode::INVALID_PROTOCOL_VERSION);
                return false;
            }

            std::vector<uint8_t> payload(handshake_data.begin() + sizeof(MessageHeader), handshake_data.end());
            HandshakeMessage client_handshake = deserialize_handshake(payload);
            LogLine(this, false) << "Received handshake init from client " << client_handshake.client_id;

            if (client_handshake.public_key_len == 0 || client_handshake.public_key_len > MAX_PUBLIC_KEY_SIZE) {
                LogLine(this, true) << "Invalid client public key length";
                return false;
            }

            // Step 2: ephemeral DH key and our own nonce, so both sides add randomness.
            KeyPair dh_keypair = crypto_manager_->generate_dh_keypair();
            if (dh_keypair.public_key.size() > MAX_PUBLIC_KEY_SIZE) {
                LogLine(this, true) << "DH public key does not fit in handshake message";
                return false;
            }
            const std::vector<uint8_t> client_key(client_handshake.public_key,
                                                  client_handshake.public_key + client_handshake.public_key_len);
            const std::vector<uint8_t> client_nonce(client_handshake.nonce, client_handshake.nonce + IV_SIZE);
            const std::vector<uint8_t> server_nonce = crypto_manager_->generate_random_bytes(IV_SIZE);

            std::vector<uint8_t> shared_secret = crypto_manager_->perform_dh_key_exchange(dh_keypair.private_key, client_key);
            std::vector<uint8_t> salt = client_nonce;
            salt.insert(salt.end(), server_nonce.begin(), server_nonce.end());
            SessionKeys keys = crypto_manager_->derive_directional_keys(shared_secret, salt, true);
            session_manager_->set_session_keys(session.session_id, keys);
            session.shared_secret = shared_secret;
            session.tx_key = keys.tx_key;
            session.rx_key = keys.rx_key;

            // Step 3: reply with our DH key and nonce, signed by our identity key.
            HandshakeMessage server_handshake{};
            server_handshake.client_id = session.client_id;
            server_handshake.session_id = session.session_id;
            server_handshake.fs_type = ForwardSecrecyType::PERFECT_FORWARD_SECRECY;
            server_handshake.public_key_len = static_cast<uint16_t>(dh_keypair.public_key.size());
            std::copy(dh_keypair.public_key.begin(), dh_keypair.public_key.end(), server_handshake.public_key);
            std::copy(server_nonce.begin(), server_nonce.end(), server_handshake.nonce);

            const std::vector<uint8_t> transcript =
                handshake_transcript(session.session_id, client_key, client_nonce, dh_keypair.public_key, server_nonce);
            const std::vector<uint8_t> signature = crypto_manager_->identity_sign(identity_, transcript);

            MessageHeader response_header{};
            response_header.version = PROTOCOL_VERSION;
            response_header.type = MessageType::HANDSHAKE_RESPONSE;
            response_header.sequence_number = 0;
            response_header.timestamp = get_current_timestamp_seconds();
            response_header.payload_size =
                static_cast<uint16_t>(sizeof(HandshakeMessage) + IDENTITY_KEY_SIZE + IDENTITY_SIGNATURE_SIZE);

            std::vector<uint8_t> response_data = serialize_header(response_header);
            std::vector<uint8_t> handshake_payload = serialize_handshake(server_handshake);
            response_data.insert(response_data.end(), handshake_payload.begin(), handshake_payload.end());
            response_data.insert(response_data.end(), identity_.public_raw.begin(), identity_.public_raw.end());
            response_data.insert(response_data.end(), signature.begin(), signature.end());

            bool sent = false;
            {
                std::lock_guard<std::mutex> lock(conn->send_mutex);
                sent = send_data(conn, response_data);
            }
            if (!sent) {
                LogLine(this, true) << "Failed to send handshake response";
                return false;
            }

            return true;

        } catch (const std::exception& e) {
            LogLine(this, true) << "Handshake error: " << e.what();
            return false;
        }
    }

    // Step 4, on the client's next frame: it confirms.
    bool handshake_confirm(const std::shared_ptr<ClientConnection>& conn, const std::vector<uint8_t>& complete_data) {
        SessionInfo& session = conn->session;
        try {
            if (complete_data.size() < sizeof(MessageHeader)) {
                LogLine(this, true) << "Handshake confirmation missing";
                return false;
            }
            MessageHeader complete_header = deserialize_header(complete_data);
            if (complete_header.type != MessageType::HANDSHAKE_COMPLETE || complete_header.version != PROTOCOL_VERSION) {
                LogLine(this, true) << "Expected HANDSHAKE_COMPLETE, got " << message_type_to_string(complete_header.type);
                return false;
            }

            session_manager_->authenticate_session(session.session_id, std::vector<uint8_t>());
            session.authenticated = true;
            LogLine(this, false) << "Handshake completed for session " << session.session_id;
            return true;

        } catch (const std::exception& e) {
            LogLine(this, true) << "Handshake error: " << e.what();
            return false;
        }
    }

    // Opens one encrypted frame from the client: checks the version and that the
    // sequence number is exactly the next one, then decrypts with the header bound
    // in as associated data. Any failure means the frame was forged, replayed,
    // reordered or altered, and the caller ends the connection.
    bool open_frame(const std::vector<uint8_t>& frame, const std::shared_ptr<ClientConnection>& conn,
                    std::vector<uint8_t>* plain) {
        if (frame.size() < sizeof(MessageHeader) + sizeof(EncryptedMessage)) {
            return false;
        }
        const MessageHeader header = deserialize_header(frame);
        if (header.version != PROTOCOL_VERSION || header.sequence_number != conn->rx_seq + 1 ||
            header.payload_size > MAX_MESSAGE_SIZE) {
            return false;
        }
        std::vector<uint8_t> body(frame.begin() + sizeof(MessageHeader), frame.end());
        EncryptedMessage msg = deserialize_encrypted_message(body);
        std::vector<uint8_t> key = session_manager_->get_rx_key(conn->session_id);
        std::vector<uint8_t> iv(msg.iv, msg.iv + IV_SIZE);
        std::vector<uint8_t> cipher(msg.encrypted_data, msg.encrypted_data + header.payload_size);
        try {
            *plain = crypto_manager_->decrypt_aes_gcm(
                cipher, key, iv, frame_aad(header.type, header.sequence_number, conn->session_id));
        } catch (const std::exception&) {
            return false;
        }
        conn->rx_seq = header.sequence_number;
        return true;
    }

    // Handles one frame from a connection that has finished the handshake.
    // False: close the connection.
    // The body was written as a loop over frames and keeps that shape: inside
    // it `continue` means "done with this frame" and `break` means "close the
    // connection". The loop below runs once; pass tells the two apart.
    bool handle_encrypted_frame(const std::shared_ptr<ClientConnection>& conn,
                                const std::vector<uint8_t>& encrypted_data) {
        SessionInfo& session = conn->session;
        int pass = 0;
        for (; pass < 1; ++pass) {
            try {

                MessageHeader header = deserialize_header(encrypted_data);
                
                if (header.type == MessageType::ENCRYPTED_MESSAGE) {
                    std::vector<uint8_t> decrypted_data;
                    if (!open_frame(encrypted_data, conn, &decrypted_data)) {
                        LogLine(this, false) << "Dropped a client after a frame that failed its integrity check";
                        break;
                    }

                    ChatMessage chat = deserialize_chat(decrypted_data);

                    if (chat.type == ChatType::REGISTER) {
                        // The room code comes first, so someone without it cannot
                        // even learn which names are taken.
                        // A banned address is told why (rather than seeing a
                        // dead line) and cut off before its room code is even
                        // looked at, so it learns nothing about the code.
                        if (banned_address(conn->peer)) {
                            ChatMessage refusal = make_chat(ChatType::REGISTER_FAIL);
                            set_chat_text(refusal, "The host banned you from this chat");
                            send_chat(conn, refusal);
                            break;
                        }
                        if (!options_.room_code.empty() && !begin_guess(conn->address)) {
                            ChatMessage refusal = make_chat(ChatType::REGISTER_FAIL);
                            set_chat_text(refusal, "Too many wrong room codes. Try again later.");
                            send_chat(conn, refusal);
                            break;
                        }
                        if (!options_.room_code.empty() &&
                            !room_code_matches(get_chat_field(chat.recipient, MAX_NAME_LEN))) {
                            // Slow down guessing, and give up on a connection after five tries.
                            guess_failed(conn->address);
                            // Nothing more from this connection is looked at for a
                            // second (sleeping here would stall everyone else).
                            conn->paused_until = std::chrono::steady_clock::now() + std::chrono::seconds(1);
                            ChatMessage refusal = make_chat(ChatType::REGISTER_FAIL);
                            set_chat_text(refusal, "Wrong room code");
                            send_chat(conn, refusal);
                            if (++conn->wrong_codes >= 5) {
                                LogLine(this, false) << "Closed a connection after five wrong room codes";
                                break;
                            }
                            continue;
                        }

                        if (!options_.room_code.empty()) {
                            guess_succeeded(conn->address);
                        }
                        // The name, then (from clients that have one) a zero
                        // byte and the person's public key for end-to-end
                        // encryption, which is only ever handed on, never used.
                        const std::string asked = get_chat_text(chat);
                        const size_t name_end = asked.find('\0');
                        const std::string wanted = asked.substr(0, name_end);
                        const std::string offered_key =
                            name_end != std::string::npos && asked.size() - name_end - 1 == E2E_KEY_SIZE
                                ? asked.substr(name_end + 1) : std::string();
                        std::string reason;
                        if (!is_valid_name(wanted)) {
                            reason = "Name must be 1-31 printable characters with no spaces, not starting with #";
                        } else if (banned_name(wanted)) {
                            reason = "The host banned you from this chat";
                        } else if (!conn->name.empty()) {
                            reason = "Already registered as " + conn->name;
                        } else if (!register_name(wanted, conn)) {
                            reason = "That name is taken";
                        }

                        ChatMessage reply = make_chat(
                            reason.empty() ? ChatType::REGISTER_OK
                                           : ChatType::REGISTER_FAIL);
                        set_chat_text(reply, reason.empty() ? wanted : reason);
                        send_chat(conn, reply);

                        if (reason.empty()) {
                            if (!conn->counted_joined) {
                                conn->counted_joined = true;
                                release_pending(conn->address);
                            }
                            LogLine(this, false) << "Registered " << wanted << " on session "
                                      << session.session_id;
                            broadcast_presence(wanted, true, wanted);
                            // In this order: what was kept is checked against the
                            // address the name had before this join.
                            deliver_kept(conn);
                            conn->e2e_key = offered_key;
                            remember_name(wanted, conn->peer, offered_key);
                        }
                        continue;
                    }

                    if (conn->name.empty()) {
                        send_notice(conn, "Register a name before sending messages");
                        continue;
                    }

                    if (chat.type == ChatType::KEY) {
                        const std::string who = get_chat_field(chat.recipient, MAX_NAME_LEN);
                        ChatMessage reply = make_chat(ChatType::KEY);
                        set_chat_field(reply.sender, MAX_NAME_LEN, who);
                        set_chat_text(reply, key_of(who));
                        send_chat(conn, reply);
                        continue;
                    }

                    if (chat.type == ChatType::DIRECT) {
                        const std::string to =
                            get_chat_field(chat.recipient, MAX_NAME_LEN);
                        std::shared_ptr<ClientConnection> target = lookup(to);
                        if (!target) {
                            // Someone who was here earlier gets it when they are back.
                            if (keep_for_later(to, conn->name, get_chat_text(chat))) {
                                send_receipt(conn, to, "queued");
                                LogLine(this, false) << conn->name << " -> " << to << " (away, kept)";
                            } else {
                                send_notice(conn, "No such user: " + to);
                            }
                            continue;
                        }

                        // sender is stamped from the registry, never from the inbound
                        // envelope, so a client cannot claim to be someone else.
                        ChatMessage out =
                            make_chat(ChatType::DIRECT);
                        set_chat_field(out.sender, MAX_NAME_LEN, conn->name);
                        set_chat_field(out.recipient, MAX_NAME_LEN, to);
                        set_chat_text(out, get_chat_text(chat));
                        send_chat(target, out);
                        send_receipt(conn, to, "delivered");

                        // Who, never what: message text stays out of the log.
                        LogLine(this, false) << conn->name << " -> " << to;
                        continue;
                    }

                    if (chat.type == ChatType::BROADCAST) {
                        ChatMessage out =
                            make_chat(ChatType::BROADCAST);
                        set_chat_field(out.sender, MAX_NAME_LEN, conn->name);
                        set_chat_text(out, get_chat_text(chat));

                        for (const auto& peer : roster_snapshot()) {
                            if (peer->name != conn->name) {
                                send_chat(peer, out);
                            }
                        }

                        LogLine(this, false) << conn->name << " -> everyone";
                        continue;
                    }

                    if (chat.type == ChatType::RECEIPT) {
                        // Only "read" comes from a client, and only to someone here.
                        std::shared_ptr<ClientConnection> target = lookup(get_chat_field(chat.recipient, MAX_NAME_LEN));
                        if (target && get_chat_text(chat) == "read") {
                            send_receipt(target, conn->name, "read");
                        }
                        continue;
                    }

                    if (chat.type == ChatType::FILE_CHUNK) {
                        // Relayed like the kind of message it rides on; the
                        // server never puts the pieces together.
                        const std::string body = get_chat_text(chat);
                        if (body.size() < FILE_CHUNK_HEADER) {
                            continue;
                        }
                        const std::string to = get_chat_field(chat.recipient, MAX_NAME_LEN);
                        // Only the first piece earns a notice, or a refused
                        // file would bring one back for every piece.
                        const bool first = body[9] == 0 && body[10] == 0 && body[11] == 0 && body[12] == 0;
                        std::vector<std::shared_ptr<ClientConnection>> targets;
                        if (body[0] == 'd') {
                            std::shared_ptr<ClientConnection> target = lookup(to);
                            if (!target) {
                                if (first) {
                                    send_notice(conn, "No such user: " + to);
                                }
                                continue;
                            }
                            targets.push_back(target);
                        } else if (body[0] == 'r') {
                            targets = room_members(to);
                            if (std::find(targets.begin(), targets.end(), conn) == targets.end()) {
                                if (first) {
                                    send_notice(conn, "You are not in the room " + to);
                                }
                                continue;
                            }
                        } else if (body[0] == 'e') {
                            targets = roster_snapshot();
                        } else {
                            continue;
                        }
                        ChatMessage out = make_chat(ChatType::FILE_CHUNK);
                        set_chat_field(out.sender, MAX_NAME_LEN, conn->name);
                        set_chat_field(out.recipient, MAX_NAME_LEN, to);
                        set_chat_text(out, body);
                        for (const auto& target : targets) {
                            if (target != conn) {
                                send_chat(target, out);
                            }
                        }
                        if (first) {
                            LogLine(this, false) << conn->name << " is sending a file";
                        }
                        continue;
                    }

                    if (chat.type == ChatType::ROOM_JOIN) {
                        const std::string room = get_chat_field(chat.recipient, MAX_NAME_LEN);
                        bool added = false;
                        const std::string problem = join_room(room, conn, &added);
                        if (!problem.empty()) {
                            send_notice(conn, problem);
                        } else if (added) {
                            // Everyone in the room hears it, the joiner included:
                            // that is how the joiner knows it worked.
                            send_room_event(room, conn->name, true, nullptr);
                            LogLine(this, false) << conn->name << " joined room " << room;
                        }
                        continue;
                    }

                    if (chat.type == ChatType::ROOM_LEAVE) {
                        const std::string room = get_chat_field(chat.recipient, MAX_NAME_LEN);
                        if (leave_room(room, conn)) {
                            send_room_event(room, conn->name, false, conn);
                            LogLine(this, false) << conn->name << " left room " << room;
                        }
                        continue;
                    }

                    if (chat.type == ChatType::ROOM_MESSAGE) {
                        const std::string room = get_chat_field(chat.recipient, MAX_NAME_LEN);
                        const auto members = room_members(room);
                        if (std::find(members.begin(), members.end(), conn) == members.end()) {
                            send_notice(conn, "You are not in the room " + room);
                            continue;
                        }
                        // The sender is stamped from the registry, as for direct messages.
                        ChatMessage out = make_chat(ChatType::ROOM_MESSAGE);
                        set_chat_field(out.sender, MAX_NAME_LEN, conn->name);
                        set_chat_field(out.recipient, MAX_NAME_LEN, room);
                        set_chat_text(out, get_chat_text(chat));
                        for (const auto& member : members) {
                            if (member != conn) {
                                send_chat(member, out);
                            }
                        }
                        LogLine(this, false) << conn->name << " -> room " << room;
                        continue;
                    }

                    if (chat.type == ChatType::ROOM_LIST) {
                        // Whole names only, like the roster.
                        std::string names;
                        for (const std::string& room : room_names()) {
                            const size_t needed = room.size() + (names.empty() ? 0 : 2);
                            if (names.size() + needed > MAX_TEXT_LEN) {
                                break;
                            }
                            if (!names.empty()) {
                                names += ", ";
                            }
                            names += room;
                        }
                        ChatMessage reply = make_chat(ChatType::ROOM_LIST);
                        set_chat_text(reply, names);
                        send_chat(conn, reply);
                        continue;
                    }

                    if (chat.type == ChatType::WHO) {
                        // The reply is one message. If the names don't all fit,
                        // stop at a whole name: a name cut in half would show
                        // up as someone who doesn't exist.
                        const auto peers = roster_snapshot();
                        const size_t count = peers.size();
                        const size_t room = MAX_TEXT_LEN - (std::string("Online (): ").size() +
                                                            std::to_string(count).size());
                        std::string names;
                        for (const auto& peer : peers) {
                            const size_t needed = peer->name.size() + (names.empty() ? 0 : 2);
                            if (names.size() + needed > room) {
                                break;
                            }
                            if (!names.empty()) {
                                names += ", ";
                            }
                            names += peer->name;
                        }
                        ChatMessage reply =
                            make_chat(ChatType::ROSTER);
                        set_chat_text(
                            reply, "Online (" + std::to_string(count) + "): " + names);
                        send_chat(conn, reply);
                        continue;
                    }

                    send_notice(conn, "Unsupported message type");

                } else if (header.type == MessageType::KEY_ROTATION) {
                    // The client is rotating the direction it sends on. The marker is
                    // encrypted under the old key, so nobody else can trigger it.
                    std::vector<uint8_t> marker;
                    if (!open_frame(encrypted_data, conn, &marker) ||
                        std::string(marker.begin(), marker.end()) != ROTATION_MARKER) {
                        LogLine(this, false) << "Dropped a client after a key rotation that failed its integrity check";
                        break;
                    }
                    session_manager_->rotate_rx_key(session.session_id);
                    LogLine(this, false) << "Client rotated its send key for session " << session.session_id;

                } else if (header.type == MessageType::ERROR_MESSAGE) {
                    LogLine(this, true) << "Received error message from client";
                    break;

                } else {
                    LogLine(this, true) << "Unknown message type: " << static_cast<int>(header.type);
                    send_error(conn, ErrorCode::INVALID_MESSAGE);
                }

            } catch (const std::exception& e) {
                LogLine(this, true) << "Error handling encrypted message: " << e.what();
                send_error(conn, ErrorCode::INTERNAL_ERROR);
                break;
            }
        }
        return pass == 1;
    }

    // Direct messages kept for people who are away. Only for names seen in this
    // run of the server, a limited number each, and only for a day. All in
    // memory: they go when the server stops.
    struct Kept {
        std::string sender;
        std::string text;
        std::chrono::steady_clock::time_point when;
    };
    std::map<std::string, std::deque<Kept>> kept_;
    std::map<std::string, std::string> seen_names_;  // name -> the address it last joined from
    std::map<std::string, std::string> seen_keys_;   // name -> the public key it last joined with
    std::mutex kept_mutex_;
    static constexpr size_t kMaxKeptPerPerson = 50;
    static constexpr size_t kMaxKeptPerSender = 10;  // of those, from any one sender
    static constexpr size_t kMaxSeenNames = 1024;

    void remember_name(const std::string& name, const std::string& address, const std::string& key) {
        std::lock_guard<std::mutex> lock(kept_mutex_);
        if (seen_names_.count(name) > 0 || seen_names_.size() < kMaxSeenNames) {
            seen_names_[name] = address;
            seen_keys_[name] = key;
        }
    }

    // The public key of someone here, or of someone away whose messages are
    // being kept (so they can be sealed for them meanwhile). Empty if unknown.
    std::string key_of(const std::string& name) {
        if (const std::shared_ptr<ClientConnection> here = lookup(name)) {
            return here->e2e_key;
        }
        std::lock_guard<std::mutex> lock(kept_mutex_);
        const auto it = seen_keys_.find(name);
        return it == seen_keys_.end() ? std::string() : it->second;
    }

    // False if the name was never here, or its queue is full.
    bool keep_for_later(const std::string& to, const std::string& sender, const std::string& text) {
        std::lock_guard<std::mutex> lock(kept_mutex_);
        if (seen_names_.count(to) == 0) {
            return false;
        }
        std::deque<Kept>& queue = kept_[to];
        // Old ones make room first, and no single sender can fill the queue.
        const auto now = std::chrono::steady_clock::now();
        while (!queue.empty() && now - queue.front().when > std::chrono::hours(24)) {
            queue.pop_front();
        }
        size_t from_sender = 0;
        for (const Kept& kept : queue) {
            from_sender += kept.sender == sender ? 1 : 0;
        }
        if (queue.size() >= kMaxKeptPerPerson || from_sender >= kMaxKeptPerSender) {
            return false;
        }
        queue.push_back(Kept{sender, text, std::chrono::steady_clock::now()});
        return true;
    }

    // Hands over what was kept for the person who just joined, oldest first,
    // and tells the senders who are still here that it arrived.
    void deliver_kept(const std::shared_ptr<ClientConnection>& conn) {
        std::deque<Kept> queue;
        {
            std::lock_guard<std::mutex> lock(kept_mutex_);
            const auto it = kept_.find(conn->name);
            if (it == kept_.end()) {
                return;
            }
            queue = std::move(it->second);
            kept_.erase(it);
            // Names aren't accounts, so anyone could take the name of someone
            // who left. What was kept goes only to the address that name was
            // last at; from anywhere else it is thrown away, not handed over.
            const auto owner = seen_names_.find(conn->name);
            if (owner == seen_names_.end() || owner->second != conn->peer) {
                LogLine(this, false) << "Dropped messages kept for " << conn->name
                                     << ": the name came back from a different address";
                return;
            }
        }
        const auto now = std::chrono::steady_clock::now();
        while (!queue.empty() && now - queue.front().when > std::chrono::hours(24)) {
            queue.pop_front();
        }
        if (queue.empty()) {
            return;
        }
        send_notice(conn, std::to_string(queue.size()) +
                              (queue.size() == 1 ? " message" : " messages") + " arrived while you were away");
        std::set<std::string> senders;
        for (const Kept& kept : queue) {
            ChatMessage out = make_chat(ChatType::DIRECT);
            set_chat_field(out.sender, MAX_NAME_LEN, kept.sender);
            set_chat_field(out.recipient, MAX_NAME_LEN, conn->name);
            set_chat_text(out, kept.text);
            send_chat(conn, out);
            senders.insert(kept.sender);
        }
        for (const std::string& sender : senders) {
            if (std::shared_ptr<ClientConnection> back = lookup(sender)) {
                send_receipt(back, conn->name, "delivered");
            }
        }
    }

    // Tells conn what became of its messages to (or was done by) about.
    void send_receipt(const std::shared_ptr<ClientConnection>& conn, const std::string& about, const std::string& what) {
        ChatMessage msg = make_chat(ChatType::RECEIPT);
        set_chat_field(msg.sender, MAX_NAME_LEN, about);
        set_chat_text(msg, what);
        send_chat(conn, msg);
    }

    // Named rooms: who is in each. A room exists while it has members, so
    // there is nothing to create or delete, and nobody owns one.
    std::map<std::string, std::set<std::shared_ptr<ClientConnection>>> rooms_;
    std::mutex rooms_mutex_;
    static constexpr size_t kMaxRooms = 64;
    static constexpr size_t kMaxRoomsPerPerson = 16;

    // Puts conn in the room. Returns what to tell the person if it can't, or
    // nothing; *added is false when they were in it already.
    std::string join_room(const std::string& room, const std::shared_ptr<ClientConnection>& conn, bool* added) {
        *added = false;
        if (!is_valid_name(room)) {
            return "Room names are 1-31 characters with no spaces, not starting with #";
        }
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        const auto it = rooms_.find(room);
        if (it != rooms_.end() && it->second.count(conn) > 0) {
            return std::string();
        }
        size_t mine = 0;
        for (const auto& entry : rooms_) {
            mine += entry.second.count(conn);
        }
        if (mine >= kMaxRoomsPerPerson) {
            return "You are in too many rooms; leave one first";
        }
        if (it == rooms_.end() && rooms_.size() >= kMaxRooms) {
            return "This chat has too many rooms";
        }
        rooms_[room].insert(conn);
        *added = true;
        return std::string();
    }

    // False if conn was not in the room.
    bool leave_room(const std::string& room, const std::shared_ptr<ClientConnection>& conn) {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        const auto it = rooms_.find(room);
        if (it == rooms_.end() || it->second.erase(conn) == 0) {
            return false;
        }
        if (it->second.empty()) {
            rooms_.erase(it);
        }
        return true;
    }

    // Takes conn out of every room; returns the rooms it was in.
    std::vector<std::string> leave_all_rooms(const std::shared_ptr<ClientConnection>& conn) {
        std::vector<std::string> left;
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        for (auto it = rooms_.begin(); it != rooms_.end();) {
            if (it->second.erase(conn) > 0) {
                left.push_back(it->first);
            }
            it = it->second.empty() ? rooms_.erase(it) : std::next(it);
        }
        return left;
    }

    // A snapshot, so nothing is sent while rooms_mutex_ is held.
    std::vector<std::shared_ptr<ClientConnection>> room_members(const std::string& room) {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        const auto it = rooms_.find(room);
        if (it == rooms_.end()) {
            return {};
        }
        return std::vector<std::shared_ptr<ClientConnection>>(it->second.begin(), it->second.end());
    }

    std::vector<std::string> room_names() {
        std::lock_guard<std::mutex> lock(rooms_mutex_);
        std::vector<std::string> names;
        for (const auto& entry : rooms_) {
            names.push_back(entry.first);
        }
        return names;
    }

    // Tells the room's members that name joined or left; also is told, when
    // given (someone who just left is no longer a member).
    void send_room_event(const std::string& room, const std::string& name, bool joined,
                         const std::shared_ptr<ClientConnection>& also) {
        ChatMessage msg = make_chat(ChatType::ROOM_EVENT);
        set_chat_field(msg.sender, MAX_NAME_LEN, name);
        set_chat_field(msg.recipient, MAX_NAME_LEN, room);
        set_chat_text(msg, joined ? "joined" : "left");
        for (const auto& member : room_members(room)) {
            send_chat(member, msg);
        }
        if (also) {
            send_chat(also, msg);
        }
    }

    bool register_name(const std::string& name, const std::shared_ptr<ClientConnection>& conn) {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        if (registry_.find(name) != registry_.end()) {
            return false;
        }
        registry_[name] = conn;
        conn->name = name;
        return true;
    }

    void unregister(const std::shared_ptr<ClientConnection>& conn) {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        if (!conn->name.empty()) {
            registry_.erase(conn->name);
        }
    }

    std::shared_ptr<ClientConnection> lookup(const std::string& name) {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        auto it = registry_.find(name);
        return it == registry_.end() ? nullptr : it->second;
    }

    // Returns a snapshot so callers can send without holding registry_mutex_.
    // Holding it across socket I/O would let one slow client stall every other.
    std::vector<std::shared_ptr<ClientConnection>> roster_snapshot() {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        std::vector<std::shared_ptr<ClientConnection>> out;
        out.reserve(registry_.size());
        for (const auto& entry : registry_) {
            out.push_back(entry.second);
        }
        return out;
    }

    // Encryption happens inside the connection's lock so a rotation cannot land
    // between encrypting and sending, and so two relaying threads cannot interleave
    // frames on one socket.
    void send_chat(const std::shared_ptr<ClientConnection>& conn, const ChatMessage& msg) {
        if (!conn->alive) {
            return;
        }
        std::lock_guard<std::mutex> lock(conn->send_mutex);
        // Recheck under the lock: the connection may have closed while we waited.
        if (!conn->alive) {
            return;
        }
        try {
            std::vector<uint8_t> frame = seal_frame(conn, MessageType::ENCRYPTED_MESSAGE, serialize_chat(msg));
            if (frame.empty()) {
                return;
            }

            if (!send_data(conn, frame)) {
                drop_locked(conn);
                return;
            }

            // Rotating here, under send_mutex, means no other relaying thread can
            // encrypt with the old key and send after the marker has gone out.
            if (++conn->sent_count % KEY_ROTATION_INTERVAL == 0) {
                if (!rotate_tx_and_announce(conn)) {
                    drop_locked(conn);
                    return;
                }
                LogLine(this, false) << "Rotated send key for session " << conn->session_id;
            }
        } catch (const std::exception&) {
            drop_locked(conn);
        }
    }

    // A send to this client failed or timed out, so its stream can no longer be
    // trusted. Cutting the socket ends its receive thread, which unregisters the
    // name; otherwise it would stay "online" and never get another message.
    // The caller holds send_mutex, so the socket has not been closed yet.
    void drop_locked(const std::shared_ptr<ClientConnection>& conn) {
        conn->alive = false;  // the loop closes it on its next pass
    }

    void broadcast_presence(const std::string& name, bool joined, const std::string& except) {
        ChatMessage msg = make_chat(ChatType::PRESENCE);
        set_chat_field(msg.sender, MAX_NAME_LEN, name);
        set_chat_text(msg, name + (joined ? " joined" : " left"));

        for (const auto& peer : roster_snapshot()) {
            if (peer->name != except) {
                send_chat(peer, msg);
            }
        }
    }

    void send_notice(const std::shared_ptr<ClientConnection>& conn, const std::string& text) {
        ChatMessage msg = make_chat(ChatType::NOTICE);
        set_chat_text(msg, text);
        send_chat(conn, msg);
    }

    // Announces that this peer is rotating the direction it sends on. The frame is
    // header-only, so it needs no key, and it goes out before the key changes. The
    // peer rotates its rx key when it reads the frame, so both switch at the same
    // point in the stream and neither direction disturbs the other. The caller must
    // hold the connection's send_mutex.
    // Builds one encrypted frame with the next sequence number and the header
    // bound in as associated data. The caller holds conn->send_mutex.
    std::vector<uint8_t> seal_frame(const std::shared_ptr<ClientConnection>& conn, MessageType type,
                                    const std::vector<uint8_t>& plain) {
        const uint32_t seq = conn->tx_seq + 1;
        std::vector<uint8_t> tx = session_manager_->get_tx_key(conn->session_id);
        std::vector<uint8_t> iv = crypto_manager_->generate_random_bytes(IV_SIZE);
        std::vector<uint8_t> cipher =
            crypto_manager_->encrypt_aes_gcm(plain, tx, iv, frame_aad(type, seq, conn->session_id));
        if (cipher.size() > MAX_MESSAGE_SIZE) {
            return {};
        }
        EncryptedMessage out{};
        out.session_id = conn->session_id;
        out.message_id = seq;
        std::copy(iv.begin(), iv.end(), out.iv);
        std::copy(cipher.begin(), cipher.end(), out.encrypted_data);

        MessageHeader header{};
        header.version = PROTOCOL_VERSION;
        header.type = type;
        header.sequence_number = seq;
        header.timestamp = get_current_timestamp_seconds();
        header.payload_size = static_cast<uint16_t>(cipher.size());

        std::vector<uint8_t> frame = serialize_header(header);
        std::vector<uint8_t> body = serialize_encrypted_message(out);
        frame.insert(frame.end(), body.begin(), body.end());
        conn->tx_seq = seq;
        return frame;
    }

    // Announces that this side is rotating the key it sends with. The marker is
    // an encrypted frame under the current key, so the client can tell it really
    // came from us; the key changes right after it. The caller holds send_mutex.
    bool rotate_tx_and_announce(const std::shared_ptr<ClientConnection>& conn) {
        const std::string marker = ROTATION_MARKER;
        std::vector<uint8_t> frame =
            seal_frame(conn, MessageType::KEY_ROTATION, std::vector<uint8_t>(marker.begin(), marker.end()));
        if (frame.empty() || !send_data(conn, frame)) {
            return false;
        }
        session_manager_->rotate_tx_key(conn->session_id);
        return true;
    }

    // Takes send_mutex like send_chat, so an error frame cannot interleave with a
    // frame another thread is relaying to the same socket.
    void send_error(const std::shared_ptr<ClientConnection>& conn, ErrorCode error_code) {
        MessageHeader header;
        header.version = PROTOCOL_VERSION;
        header.type = MessageType::ERROR_MESSAGE;
        header.sequence_number = 0;
        header.timestamp = get_current_timestamp_seconds();
        header.payload_size = sizeof(ErrorCode);
        header.flags = 0;

        std::vector<uint8_t> response_data = serialize_header(header);
        std::vector<uint8_t> error_data(reinterpret_cast<const uint8_t*>(&error_code), 
                                       reinterpret_cast<const uint8_t*>(&error_code) + sizeof(ErrorCode));
        response_data.insert(response_data.end(), error_data.begin(), error_data.end());

        std::lock_guard<std::mutex> lock(conn->send_mutex);
        if (conn->alive) {
            send_data(conn, response_data);
        }
    }

    // Writes as much queued output as the socket will take right now. The
    // caller holds conn->send_mutex.
    void flush_locked(const std::shared_ptr<ClientConnection>& conn) {
        while (!conn->out.empty() && conn->socket >= 0) {
            const size_t chunk = (std::min<size_t>)(conn->out.size(), 256 * 1024);
            const int sent = send(static_cast<socket_t>(conn->socket), reinterpret_cast<const char*>(conn->out.data()),
                                  static_cast<int>(chunk), kSendFlags);
            if (sent > 0) {
                conn->out.erase(conn->out.begin(), conn->out.begin() + sent);
                conn->out_progress = std::chrono::steady_clock::now();
                conn->out_window_sent += static_cast<size_t>(sent);
            } else {
                if (!would_block()) {
                    conn->alive = false;
                }
                return;
            }
        }
    }

    // Queues one frame behind its 4-byte big-endian length and writes what the
    // socket will take; the loop writes the rest as the client reads. False if
    // the connection is closed or far too much is already waiting for it. The
    // caller holds conn->send_mutex.
    bool send_data(const std::shared_ptr<ClientConnection>& conn, const std::vector<uint8_t>& data) {
        if (conn->socket < 0 || conn->out.size() + data.size() + 4 > kMaxQueuedOutput) {
            return false;
        }
        if (conn->out.empty()) {
            conn->out_progress = std::chrono::steady_clock::now();
        }
        const uint32_t length = static_cast<uint32_t>(data.size());
        const uint8_t prefix[4] = {static_cast<uint8_t>(length >> 24), static_cast<uint8_t>(length >> 16),
                                   static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)};
        conn->out.insert(conn->out.end(), prefix, prefix + 4);
        conn->out.insert(conn->out.end(), data.begin(), data.end());
        flush_locked(conn);
        return true;
    }
};


LogLine::~LogLine() {
    if (server_->options_.log) {
        server_->options_.log(out_.str(), is_error_);
    }
}

SecureServer::SecureServer(ServerOptions options) : impl_(std::make_unique<Impl>(std::move(options))) {}

SecureServer::~SecureServer() = default;

bool SecureServer::start(std::string* error) {
    return impl_->start(error);
}

void SecureServer::run() {
    impl_->run();
}

void SecureServer::stop() {
    impl_->stop();
}

bool SecureServer::kick(const std::string& name) {
    return impl_->kick(name);
}

bool SecureServer::ban(const std::string& name) {
    return impl_->ban(name);
}

SecureServer::Bans SecureServer::bans() const {
    return impl_->bans();
}

void SecureServer::clear_bans() {
    impl_->clear_bans();
}

bool SecureServer::set_room_code(const std::string& code) {
    return impl_->set_room_code(code);
}

size_t SecureServer::people() const {
    return impl_->people();
}

uint16_t SecureServer::port() const {
    return impl_->options_.port;
}

std::vector<uint8_t> SecureServer::identity_public() const {
    return impl_->identity_public();
}

} // namespace SecureComm
