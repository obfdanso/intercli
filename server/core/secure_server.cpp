#include "secure_server.h"
#include "../../crypto/crypto_utils.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
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

// Waits up to timeout_ms for the socket to become readable: > 0 ready, 0 timed
// out, < 0 error. Blocking calls are polled this way so threads notice a shutdown:
// on Windows, neither shutdown() nor a signal interrupts a recv() or accept()
// already in progress.
// poll() rather than select(): FD_SET on a descriptor >= FD_SETSIZE writes out of bounds.
static void shutdown_socket(intptr_t s) {
#ifdef _WIN32
    shutdown(static_cast<SOCKET>(s), SD_BOTH);
#else
    shutdown(static_cast<int>(s), SHUT_RDWR);
#endif
}

static void set_send_timeout(intptr_t s, int ms) {
#ifdef _WIN32
    const DWORD value = static_cast<DWORD>(ms);
    setsockopt(static_cast<SOCKET>(s), SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&value), sizeof(value));
#else
    timeval value{ms / 1000, (ms % 1000) * 1000};
    setsockopt(static_cast<int>(s), SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value));
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

static int wait_readable(intptr_t s, int timeout_ms) {
    pollfd p{};
    p.events = POLLIN;
#ifdef _WIN32
    p.fd = static_cast<SOCKET>(s);
    return WSAPoll(&p, 1, timeout_ms);
#else
    p.fd = static_cast<int>(s);
    return poll(&p, 1, timeout_ms);
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
    std::string       address;         // the client's IP address
    bool              counted_joined = false;  // released from the pending count
    std::atomic<bool> alive{true};
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
    bool room_code_matches(const std::string& typed) const {
        const std::string candidate = normalize_room_code(typed);
        const std::string& code = options_.room_code;
        if (candidate.size() != code.size()) {
            return false;
        }
        return CRYPTO_memcmp(candidate.data(), code.data(), code.size()) == 0;
    }
    IdentityKey identity_;

    explicit Impl(ServerOptions options)
        : options_(std::move(options)), server_socket_(-1), running_(false) {
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

    void run() {
        while (running_) {
            if (wait_readable(server_socket_, 500) <= 0) {
                continue;
            }

            struct sockaddr_storage client_addr {};
            socklen_t client_len = sizeof(client_addr);

            intptr_t client_socket = static_cast<intptr_t>(accept(static_cast<socket_t>(server_socket_), (struct sockaddr*)&client_addr, &client_len));
            if (client_socket < 0) {
                if (running_) {
                    LogLine(this, true) << "Failed to accept client connection";
                    // Out of descriptors, say: don't spin on the same failure.
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                continue;
            }

            // An IPv4 client on the shared socket arrives as ::ffff:a.b.c.d; it
            // is named a.b.c.d, so one machine is one address for the lockouts.
            char addr_text[INET6_ADDRSTRLEN + 4] = "?";
            uint16_t client_port = 0;
            if (client_addr.ss_family == AF_INET6) {
                const auto* a = reinterpret_cast<const struct sockaddr_in6*>(&client_addr);
                client_port = ntohs(a->sin6_port);
                if (IN6_IS_ADDR_V4MAPPED(&a->sin6_addr)) {
                    inet_ntop(AF_INET, a->sin6_addr.s6_addr + 12, addr_text, sizeof(addr_text));
                } else if (IN6_IS_ADDR_LOOPBACK(&a->sin6_addr)) {
                    inet_ntop(AF_INET6, &a->sin6_addr, addr_text, sizeof(addr_text));
                } else {
                    // One machine can use any address in its /64 network, so the
                    // network is what gets counted and locked out: changing
                    // address must not buy more room code guesses.
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
                continue;
            }

            auto conn = std::make_shared<ClientConnection>();
            conn->socket = client_socket;
            conn->address = addr_text;
            // A client that stops reading must not hold a relay forever.
            set_send_timeout(client_socket, 5000);
            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                connections_.insert(conn);
            }

            // Threads are detached; stop() waits on connections_ instead of joining,
            // so finished threads do not pile up for the life of the server.
            std::thread(&Impl::handle_client, this, conn).detach();
        }
    }

    void stop() {
        running_ = false;

        const intptr_t listener = server_socket_.exchange(-1);
        if (listener >= 0) {
            close_socket(listener);
        }

        // Cut every connection now. A relay to a client that has stopped
        // reading can be stuck in send(); shutting the socket down wakes it,
        // so ending the chat never waits on someone else's connection.
        std::unique_lock<std::mutex> lock(connections_mutex_);
        for (const auto& c : connections_) {
            shutdown_socket(c->socket);
        }
        // Each client thread then notices and finishes on its own.
        connections_cv_.wait(lock, [this] { return connections_.empty(); });
    }

    size_t people() {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        return registry_.size();
    }

    std::vector<uint8_t> identity_public() const {
        return identity_.public_raw;
    }

    void handle_client(std::shared_ptr<ClientConnection> conn) {
        try {
            uint32_t client_id = generate_client_id();
            SessionInfo session = session_manager_->create_session(client_id);
            conn->session_id = session.session_id;

            LogLine(this, false) << "Created session " << session.session_id << " for client " << client_id;

            if (!perform_handshake(conn->socket, session)) {
                LogLine(this, true) << "Handshake failed for client " << client_id;
            } else {
                LogLine(this, false) << "Handshake completed successfully for client " << client_id;
                handle_encrypted_messages(conn, session);
            }

        } catch (const std::exception& e) {
            LogLine(this, true) << "Error handling client: " << e.what();
        }

        conn->alive = false;
        if (!conn->counted_joined) {
            release_pending(conn->address);
        }
        const std::string departed = conn->name;
        unregister(conn);
        if (!departed.empty()) {
            broadcast_presence(departed, false, std::string());
        }
        if (conn->session_id != 0) {
            session_manager_->remove_session(conn->session_id);
        }
        LogLine(this, false) << "Client disconnected";

        // Order matters here:
        // 1. shutdown wakes any relay stuck sending to this client (stop() may
        //    be waiting on it), without freeing the descriptor;
        // 2. the entry leaves the list, so stop() never touches this socket
        //    again (it only cuts sockets of connections still listed);
        // 3. the socket is closed under send_mutex, so a relaying thread cannot
        //    write to it mid-close, or to a connection that reuses the
        //    descriptor afterwards. conn stays alive through our shared_ptr.
        shutdown_socket(conn->socket);
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            connections_.erase(conn);
            // stop() may return (and the server go away) once this is seen;
            // nothing below touches the server.
            connections_cv_.notify_all();
        }
        std::lock_guard<std::mutex> send_lock(conn->send_mutex);
        close_socket(conn->socket);
        conn->socket = -1;
    }

    // Sends a header-only error frame on a socket not yet tied to a connection.
    void send_raw_error(intptr_t client_socket, ErrorCode code) {
        MessageHeader header{};
        header.version = PROTOCOL_VERSION;
        header.type = MessageType::ERROR_MESSAGE;
        header.timestamp = get_current_timestamp_seconds();
        header.payload_size = sizeof(ErrorCode);
        std::vector<uint8_t> frame = serialize_header(header);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&code);
        frame.insert(frame.end(), p, p + sizeof(ErrorCode));
        send_data(client_socket, frame);
    }

    bool perform_handshake(intptr_t client_socket, SessionInfo& session) {
        try {
            const auto deadline = std::chrono::steady_clock::now() + kHandshakeTimeout;

            // Step 1: receive the client's hello.
            std::vector<uint8_t> handshake_data = receive_data(client_socket, &deadline);
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
                send_raw_error(client_socket, ErrorCode::INVALID_PROTOCOL_VERSION);
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

            if (!send_data(client_socket, response_data)) {
                LogLine(this, true) << "Failed to send handshake response";
                return false;
            }

            // Step 4: the client confirms.
            std::vector<uint8_t> complete_data = receive_data(client_socket, &deadline);
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

    void handle_encrypted_messages(const std::shared_ptr<ClientConnection>& conn,
                                   SessionInfo& session) {
        const intptr_t client_socket = conn->socket;

        while (running_) {
            try {
                std::vector<uint8_t> encrypted_data = receive_data(client_socket);
                if (encrypted_data.empty()) {
                    break; // Client disconnected
                }

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
                            std::this_thread::sleep_for(std::chrono::seconds(1));
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
                        const std::string wanted = get_chat_text(chat);
                        std::string reason;
                        if (!is_valid_name(wanted)) {
                            reason = "Name must be 1-31 printable characters with no spaces";
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
                        }
                        continue;
                    }

                    if (conn->name.empty()) {
                        send_notice(conn, "Register a name before sending messages");
                        continue;
                    }

                    if (chat.type == ChatType::DIRECT) {
                        const std::string to =
                            get_chat_field(chat.recipient, MAX_NAME_LEN);
                        std::shared_ptr<ClientConnection> target = lookup(to);
                        if (!target) {
                            send_notice(conn, "No such user: " + to);
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

            if (!send_data(conn->socket, frame)) {
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
        conn->alive = false;
        shutdown_socket(conn->socket);
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
        if (frame.empty() || !send_data(conn->socket, frame)) {
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
            send_data(conn->socket, response_data);
        }
    }

    // deadline, when given, is the latest the whole read may take.
    bool receive_all(intptr_t client_socket, uint8_t* data, size_t length,
                     const std::chrono::steady_clock::time_point* deadline = nullptr) {
        size_t total = 0;
        while (total < length) {
            if (deadline && std::chrono::steady_clock::now() >= *deadline) {
                return false;
            }
            const int ready = wait_readable(client_socket, 500);
            if (ready < 0 || (ready == 0 && !running_)) {
                return false;
            }
            if (ready == 0) {
                continue;
            }
            int received = recv(static_cast<socket_t>(client_socket), reinterpret_cast<char*>(data + total),
                                static_cast<int>(length - total), 0);
            if (received <= 0) {
                return false;
            }
            total += static_cast<size_t>(received);
        }
        return true;
    }

    std::vector<uint8_t> receive_data(intptr_t client_socket,
                                      const std::chrono::steady_clock::time_point* deadline = nullptr) {
        uint32_t length_be = 0;
        if (!receive_all(client_socket, reinterpret_cast<uint8_t*>(&length_be), sizeof(length_be), deadline)) {
            return std::vector<uint8_t>();
        }

        uint32_t length = ntohl(length_be);
        if (length == 0 || length > MAX_FRAME_SIZE) {
            return std::vector<uint8_t>();
        }

        std::vector<uint8_t> buffer(length);
        if (!receive_all(client_socket, buffer.data(), length, deadline)) {
            return std::vector<uint8_t>();
        }
        return buffer;
    }

    bool send_all(intptr_t client_socket, const uint8_t* data, size_t length) {
        size_t total = 0;
        while (total < length) {
            int sent = send(static_cast<socket_t>(client_socket), reinterpret_cast<const char*>(data + total),
                            static_cast<int>(length - total), kSendFlags);
            if (sent <= 0) {
                return false;
            }
            total += static_cast<size_t>(sent);
        }
        return true;
    }

    // Every message is framed with a 4-byte big-endian length so that a message
    // larger than one recv() buffer, or split across TCP segments, still arrives whole.
    bool send_data(intptr_t client_socket, const std::vector<uint8_t>& data) {
        uint32_t length = htonl(static_cast<uint32_t>(data.size()));
        if (!send_all(client_socket, reinterpret_cast<const uint8_t*>(&length), sizeof(length))) {
            return false;
        }
        return send_all(client_socket, data.data(), data.size());
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
