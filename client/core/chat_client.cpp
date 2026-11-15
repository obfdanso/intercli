#include "chat_client.h"
#include "../../crypto/crypto_utils.h"

#include <algorithm>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <mstcpip.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <cerrno>
    #include <sys/select.h>
    #include <netinet/tcp.h>
#endif

namespace SecureComm {

namespace {

#ifdef _WIN32
using socket_t = SOCKET;
#else
using socket_t = int;
#endif

void close_raw(intptr_t s) {
#ifdef _WIN32
    closesocket(static_cast<socket_t>(s));
#else
    close(static_cast<socket_t>(s));
#endif
}

void shutdown_raw(intptr_t s) {
#ifdef _WIN32
    shutdown(static_cast<socket_t>(s), SD_BOTH);
#else
    shutdown(static_cast<socket_t>(s), SHUT_RDWR);
#endif
}

constexpr int kConnectTimeoutMs = 10000;

// Probe an idle connection after 30 s, then every 5 s, so a network that
// silently disappears (Wi-Fi off, cable out) is noticed in about a minute.
void enable_keepalive(intptr_t raw) {
    const auto s = static_cast<socket_t>(raw);
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&on), sizeof(on));
#ifdef _WIN32
    tcp_keepalive vals = {1, 30000, 5000};
    DWORD returned = 0;
    WSAIoctl(s, SIO_KEEPALIVE_VALS, &vals, sizeof(vals), nullptr, 0, &returned, nullptr, nullptr);
#elif defined(TCP_KEEPIDLE)
    int idle = 30, interval = 5, count = 6;
    setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
    setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
#endif
}
constexpr int kHandshakeTimeoutMs = 10000;

MessageHeader make_header(MessageType type, uint32_t sequence, uint16_t payload_size) {
    MessageHeader header{};
    header.version = PROTOCOL_VERSION;
    header.type = type;
    header.sequence_number = sequence;
    header.timestamp = get_current_timestamp_seconds();
    header.payload_size = payload_size;
    header.flags = 0;
    return header;
}

} // namespace

std::vector<std::string> parse_roster(const std::string& text) {
    std::vector<std::string> names;
    const std::string prefix = "Online (";
    if (text.rfind(prefix, 0) != 0) {
        return names;
    }
    const size_t list_start = text.find("): ");
    if (list_start == std::string::npos) {
        return names;
    }
    const std::string list = text.substr(list_start + 3);
    size_t pos = 0;
    while (pos <= list.size()) {
        const size_t next = list.find(", ", pos);
        const std::string name = list.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
        if (!name.empty()) {
            names.push_back(name);
        }
        if (next == std::string::npos) {
            break;
        }
        pos = next + 2;
    }
    return names;
}

ChatClient::ChatClient(ChatEvents events)
    : events_(std::move(events)), crypto_(std::make_unique<CryptoManager>()), session_{} {
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        throw std::runtime_error("WSAStartup failed");
    }
#endif
}

ChatClient::~ChatClient() {
    disconnect();
#ifdef _WIN32
    WSACleanup();
#endif
}

void ChatClient::log(const std::string& line) {
    if (events_.on_log) {
        events_.on_log(line);
    }
}

bool ChatClient::connect(const std::string& host, uint16_t port, std::string* error) {
    disconnect();
    user_disconnect_ = false;

    auto fail = [&](const std::string& reason) {
        if (error) {
            *error = reason;
        }
        close_socket();
        return false;
    };

    if (cancelled_) {
        return fail("Cancelled");
    }
    if (!connect_socket(host, port, error)) {
        close_socket();
        return false;
    }

    log("Connected to server " + host + ":" + std::to_string(port));

    // A server that accepts but never answers must not hold the handshake forever.
    set_receive_timeout(kHandshakeTimeoutMs);
    std::string handshake_error;
    if (!perform_handshake(&handshake_error)) {
        log(handshake_error);
        if (error) {
            const std::string where = host + ":" + std::to_string(port);
            if (cancelled_) {
                *error = "Cancelled";
            } else if (handshake_error.rfind("This chat's identity", 0) == 0 ||
                       handshake_error.rfind("The other side uses", 0) == 0) {
                *error = handshake_error;
            } else if (handshake_error == "No handshake response received") {
                *error = "The server at " + where + " didn't answer";
            } else {
                *error = "The secure handshake with " + where + " failed";
            }
        }
        close_socket();
        return false;
    }
    set_receive_timeout(0);

    log("Secure connection established");

    {
        std::lock_guard<std::mutex> lock(send_mutex_);
        message_counter_ = 0;
        send_rotations_ = 0;
        last_send_rotation_.reset();
    }
    connected_ = true;
    receive_thread_ = std::thread(&ChatClient::receive_loop, this);
    return true;
}

// Connects without blocking for longer than kConnectTimeoutMs, checking for
// cancel() every 100 ms. The socket is published in socket_ before connecting so
// cancel() can reach it.
bool ChatClient::connect_socket(const std::string& host, uint16_t port, std::string* error) {
    auto fail = [&](const std::string& reason) {
        if (error) {
            *error = reason;
        }
        return false;
    };

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* results = nullptr;
    const std::string port_text = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_text.c_str(), &hints, &results) != 0 || !results) {
        return fail("Couldn't find the server " + host);
    }

    bool connected = false;
    for (addrinfo* ai = results; ai && !connected && !cancelled_; ai = ai->ai_next) {
        socket_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#ifdef _WIN32
        if (s == INVALID_SOCKET) continue;
        u_long nonblocking = 1;
        ioctlsocket(s, FIONBIO, &nonblocking);
#else
        if (s < 0) continue;
        fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
#endif
        socket_ = static_cast<intptr_t>(s);

        int rc = ::connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
#ifdef _WIN32
        const bool pending = rc != 0 && WSAGetLastError() == WSAEWOULDBLOCK;
#else
        const bool pending = rc != 0 && errno == EINPROGRESS;
#endif
        if (rc == 0) {
            connected = true;
        } else if (pending) {
            for (int waited = 0; waited < kConnectTimeoutMs && !cancelled_; waited += 100) {
                fd_set writable;
                fd_set failed;
                FD_ZERO(&writable);
                FD_ZERO(&failed);
                FD_SET(s, &writable);
                FD_SET(s, &failed);
                timeval tv{0, 100 * 1000};
                const int ready = select(static_cast<int>(s) + 1, nullptr, &writable, &failed, &tv);
                if (ready < 0) {
                    break;
                }
                if (ready > 0) {
                    int so_error = 0;
                    socklen_t len = sizeof(so_error);
                    getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &len);
                    connected = FD_ISSET(s, &writable) && so_error == 0;
                    break;
                }
            }
        }

        if (connected) {
#ifdef _WIN32
            u_long blocking = 0;
            ioctlsocket(s, FIONBIO, &blocking);
#else
            fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) & ~O_NONBLOCK);
#endif
            enable_keepalive(static_cast<intptr_t>(s));
        } else {
            close_socket();
        }
    }
    freeaddrinfo(results);

    if (cancelled_) {
        return fail("Cancelled");
    }
    if (!connected) {
        return fail("Couldn't reach " + host + ":" + port_text);
    }
    return true;
}

void ChatClient::set_receive_timeout(int ms) {
    const intptr_t s = socket_.load();
    if (s < 0) {
        return;
    }
#ifdef _WIN32
    const DWORD value = static_cast<DWORD>(ms);
    setsockopt(static_cast<socket_t>(s), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&value), sizeof(value));
#else
    timeval value{ms / 1000, (ms % 1000) * 1000};
    setsockopt(static_cast<socket_t>(s), SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value));
#endif
}

void ChatClient::cancel() {
    cancelled_ = true;
    user_disconnect_ = true;
    // Closing (not just shutting down) the socket is what wakes a recv that the
    // peer will never answer; a pending connect notices the flag instead.
    const intptr_t s = socket_.exchange(-1);
    if (s >= 0) {
        shutdown_raw(s);
        close_raw(s);
    }
}

void ChatClient::close_socket() {
    const intptr_t s = socket_.exchange(-1);
    if (s >= 0) {
        close_raw(s);
    }
}

void ChatClient::disconnect() {
    user_disconnect_ = true;
    connected_ = false;

    const intptr_t s = socket_.load();
    if (s >= 0) {
        // Unblocks the receive thread, which would otherwise sit in recv forever.
        shutdown_raw(s);
    }

    if (receive_thread_.joinable()) {
        if (receive_thread_.get_id() == std::this_thread::get_id()) {
            // Called from a callback: the thread ends once the callback returns,
            // and the next disconnect() or the destructor joins it.
            return;
        }
        receive_thread_.join();
    }

    std::lock_guard<std::mutex> lock(send_mutex_);
    close_socket();
}

void ChatClient::fail_receive_for_test() {
    report_lost("Receive error: test");
}

void ChatClient::drop_connection_for_test() {
    const intptr_t s = socket_.load();
    if (s >= 0) {
        shutdown_raw(s);
    }
}

bool ChatClient::keepalive_enabled() const {
    const intptr_t s = socket_.load();
    if (s < 0) {
        return false;
    }
    int on = 0;
    socklen_t len = sizeof(on);
    getsockopt(static_cast<socket_t>(s), SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<char*>(&on), &len);
    return on != 0;
}

void ChatClient::set_expected_identity(std::vector<uint8_t> public_raw) {
    expected_identity_ = std::move(public_raw);
}

std::vector<uint8_t> ChatClient::server_identity() const {
    return server_identity_;
}

bool ChatClient::connected() const {
    return connected_;
}

SessionStatus ChatClient::status() const {
    SessionStatus st;
    st.connected = connected_;
    {
        std::lock_guard<std::mutex> lock(send_mutex_);
        st.send_rotations = send_rotations_;
        st.messages_until_rotation = KEY_ROTATION_INTERVAL - (message_counter_ % KEY_ROTATION_INTERVAL);
        st.last_send_rotation = last_send_rotation_;
    }
    {
        std::lock_guard<std::mutex> lock(rx_mutex_);
        st.receive_rotations = receive_rotations_;
    }
    return st;
}

bool ChatClient::request_name(const std::string& name, const std::string& room_code) {
    ChatMessage msg = make_chat(ChatType::REGISTER);
    set_chat_text(msg, name);
    // The code travels in the otherwise unused recipient field, inside the
    // encrypted channel to the (now authenticated) server.
    set_chat_field(msg.recipient, MAX_NAME_LEN, normalize_room_code(room_code));
    return send_chat(msg);
}

bool ChatClient::send_direct(const std::string& to, const std::string& text) {
    // An over-long name is truncated by set_chat_field, as the client always
    // did; the server then answers "No such user".
    if (text.size() > MAX_TEXT_LEN || to.empty()) {
        return false;
    }
    ChatMessage msg = make_chat(ChatType::DIRECT);
    set_chat_field(msg.recipient, MAX_NAME_LEN, to);
    set_chat_text(msg, text);
    return send_chat(msg);
}

bool ChatClient::send_broadcast(const std::string& text) {
    if (text.size() > MAX_TEXT_LEN) {
        return false;
    }
    ChatMessage msg = make_chat(ChatType::BROADCAST);
    set_chat_text(msg, text);
    return send_chat(msg);
}

bool ChatClient::request_roster() {
    return send_chat(make_chat(ChatType::WHO));
}

bool ChatClient::rotate_send_key() {
    bool ok;
    {
        std::lock_guard<std::mutex> lock(send_mutex_);
        ok = connected_ && rotate_locked();
    }
    if (ok && events_.on_send_key_rotated) {
        events_.on_send_key_rotated();
    }
    return ok;
}

bool ChatClient::send_chat(const ChatMessage& chat) {
    if (!connected_) {
        return false;
    }

    bool rotated = false;
    {
        std::lock_guard<std::mutex> lock(send_mutex_);
        try {
            std::vector<uint8_t> request_data = seal_frame(MessageType::ENCRYPTED_MESSAGE, serialize_chat(chat));
            if (request_data.empty()) {
                return false;
            }

            if (!send_data(request_data)) {
                log("Failed to send encrypted message");
                return false;
            }

            message_counter_++;

            // Rotate the direction this peer sends on every 10 messages, matching
            // what the server does for its own direction.
            if (message_counter_ % KEY_ROTATION_INTERVAL == 0) {
                rotated = rotate_locked();
            }
        } catch (const std::exception& e) {
            log(std::string("Failed to send encrypted message: ") + e.what());
            return false;
        }
    }

    if (rotated && events_.on_send_key_rotated) {
        events_.on_send_key_rotated();
    }
    return true;
}

// Announces that this peer is rotating the direction it sends on. The frame is
// header-only, so it needs no key, and it goes out before the key changes. The
// peer rotates its rx key when it reads the frame, so both switch at the same
// point in the stream. The caller holds send_mutex_.
bool ChatClient::rotate_locked() {
    try {
        const std::string marker = ROTATION_MARKER;
        std::vector<uint8_t> frame =
            seal_frame(MessageType::KEY_ROTATION, std::vector<uint8_t>(marker.begin(), marker.end()));
        if (frame.empty() || !send_data(frame)) {
            log("Failed to send key rotation marker");
            return false;
        }
        tx_key_ = crypto_->rotate_session_key(tx_key_, session_id_bytes());
        ++send_rotations_;
        last_send_rotation_ = std::chrono::system_clock::now();
        return true;
    } catch (const std::exception& e) {
        log(std::string("Key rotation failed: ") + e.what());
        return false;
    }
}

// One encrypted frame with the next sequence number and the header bound in as
// associated data. The caller holds send_mutex_.
std::vector<uint8_t> ChatClient::seal_frame(MessageType type, const std::vector<uint8_t>& plain) {
    const uint32_t seq = tx_seq_ + 1;
    std::vector<uint8_t> iv = crypto_->generate_random_bytes(IV_SIZE);
    std::vector<uint8_t> cipher =
        crypto_->encrypt_aes_gcm(plain, tx_key_, iv, frame_aad(type, seq, session_.session_id));
    if (cipher.size() > MAX_MESSAGE_SIZE) {
        return {};
    }
    EncryptedMessage msg{};
    msg.session_id = session_.session_id;
    msg.message_id = seq;
    std::copy(iv.begin(), iv.end(), msg.iv);
    std::copy(cipher.begin(), cipher.end(), msg.encrypted_data);

    MessageHeader header = make_header(type, seq, static_cast<uint16_t>(cipher.size()));
    std::vector<uint8_t> frame = serialize_header(header);
    std::vector<uint8_t> body = serialize_encrypted_message(msg);
    frame.insert(frame.end(), body.begin(), body.end());
    tx_seq_ = seq;
    return frame;
}

// Checks the version and that the frame is exactly the next one, then decrypts
// with the header bound in. False means forged, replayed, reordered or altered.
bool ChatClient::open_frame(const std::vector<uint8_t>& frame, std::vector<uint8_t>* plain) {
    if (frame.size() < sizeof(MessageHeader) + sizeof(EncryptedMessage)) {
        return false;
    }
    const MessageHeader header = deserialize_header(frame);
    if (header.version != PROTOCOL_VERSION || header.sequence_number != rx_seq_ + 1 ||
        header.payload_size > MAX_MESSAGE_SIZE) {
        return false;
    }
    std::vector<uint8_t> body(frame.begin() + sizeof(MessageHeader), frame.end());
    EncryptedMessage msg = deserialize_encrypted_message(body);
    std::vector<uint8_t> rx;
    {
        std::lock_guard<std::mutex> lock(rx_mutex_);
        rx = rx_key_;
    }
    std::vector<uint8_t> iv(msg.iv, msg.iv + IV_SIZE);
    std::vector<uint8_t> cipher(msg.encrypted_data, msg.encrypted_data + header.payload_size);
    try {
        *plain = crypto_->decrypt_aes_gcm(cipher, rx, iv,
                                          frame_aad(header.type, header.sequence_number, session_.session_id));
    } catch (const std::exception&) {
        return false;
    }
    rx_seq_ = header.sequence_number;
    return true;
}

void ChatClient::report_lost(const std::string& reason) {
    // connected_ is cleared by whoever gets here first; user disconnects stay silent.
    const bool was_connected = connected_.exchange(false);
    if (was_connected && !user_disconnect_ && events_.on_disconnected) {
        events_.on_disconnected(reason);
    }
}

void ChatClient::handle_chat(const ChatMessage& msg) {
    const std::string text = get_chat_text(msg);
    const std::string from = get_chat_field(msg.sender, MAX_NAME_LEN);

    switch (msg.type) {
        case ChatType::REGISTER_OK:
            if (events_.on_registered) events_.on_registered(text);
            break;
        case ChatType::REGISTER_FAIL:
            if (events_.on_register_failed) events_.on_register_failed(text);
            break;
        case ChatType::DIRECT:
            if (events_.on_direct) events_.on_direct(from, text);
            break;
        case ChatType::BROADCAST:
            if (events_.on_broadcast) events_.on_broadcast(from, text);
            break;
        case ChatType::NOTICE:
            if (events_.on_notice) events_.on_notice(text);
            break;
        case ChatType::ROSTER:
            if (events_.on_roster) events_.on_roster(parse_roster(text), text);
            break;
        case ChatType::PRESENCE: {
            const std::string joined_suffix = " joined";
            const bool joined = text.size() >= joined_suffix.size() &&
                text.compare(text.size() - joined_suffix.size(), joined_suffix.size(), joined_suffix) == 0;
            if (events_.on_presence) events_.on_presence(from, joined, text);
            break;
        }
        default:
            break;
    }
}

void ChatClient::dispatch_frame(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(MessageHeader)) {
        throw std::runtime_error("Frame shorter than a header");
    }
    MessageHeader header = deserialize_header(data);

    if (header.type == MessageType::KEY_ROTATION) {
        // The server is rotating the direction it sends on. The marker is
        // encrypted under the old key, so nobody else can trigger it.
        std::vector<uint8_t> marker;
        if (!open_frame(data, &marker) || std::string(marker.begin(), marker.end()) != ROTATION_MARKER) {
            throw std::runtime_error("A key rotation failed its integrity check");
        }
        {
            std::lock_guard<std::mutex> lock(rx_mutex_);
            rx_key_ = crypto_->rotate_session_key(rx_key_, session_id_bytes());
            ++receive_rotations_;
        }
        if (events_.on_receive_key_rotated) {
            events_.on_receive_key_rotated();
        }
        return;
    }

    if (header.type == MessageType::ERROR_MESSAGE) {
        std::vector<uint8_t> payload(data.begin() + sizeof(MessageHeader), data.end());
        if (payload.size() >= sizeof(ErrorCode)) {
            ErrorCode code;
            std::memcpy(&code, payload.data(), sizeof(code));
            if (events_.on_server_error) {
                events_.on_server_error(error_code_to_string(code));
            }
        }
        return;
    }

    if (header.type != MessageType::ENCRYPTED_MESSAGE) {
        return;
    }

    std::vector<uint8_t> plain;
    if (!open_frame(data, &plain)) {
        throw std::runtime_error("A message failed its integrity check");
    }

    handle_chat(deserialize_chat(plain));
}

void ChatClient::receive_loop() {
    while (connected_) {
        std::vector<uint8_t> data = receive_data();
        if (data.empty()) {
            report_lost("Connection to the server was lost");
            break;
        }
        try {
            dispatch_frame(data);
        } catch (const std::exception& e) {
            report_lost(std::string("Receive error: ") + e.what());
            break;
        }
    }
}

std::vector<uint8_t> ChatClient::session_id_bytes() const {
    const uint32_t id = session_.session_id;
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&id),
                                reinterpret_cast<const uint8_t*>(&id) + sizeof(id));
}

bool ChatClient::perform_handshake(std::string* error) {
    auto fail = [&](const std::string& reason) {
        if (error) {
            *error = reason;
        }
        return false;
    };

    try {
        // Step 1: send handshake init
        session_ = SessionInfo{};
        session_.client_id = generate_client_id();
        session_.session_id = generate_session_id();

        HandshakeMessage handshake{};
        handshake.client_id = session_.client_id;
        handshake.session_id = session_.session_id;
        handshake.fs_type = ForwardSecrecyType::PERFECT_FORWARD_SECRECY;

        // An ephemeral DH key of the same group as the server's.
        dh_keypair_ = crypto_->generate_dh_keypair();
        if (dh_keypair_.public_key.size() > MAX_PUBLIC_KEY_SIZE) {
            return fail("DH public key does not fit in handshake message");
        }
        handshake.public_key_len = static_cast<uint16_t>(dh_keypair_.public_key.size());
        std::copy(dh_keypair_.public_key.begin(), dh_keypair_.public_key.end(), handshake.public_key);

        // The nonce salts the session key derivation, so draw it from OpenSSL's
        // CSPRNG rather than the predictable mt19937 behind generate_nonce.
        std::vector<uint8_t> nonce = crypto_->generate_random_bytes(IV_SIZE);
        std::copy(nonce.begin(), nonce.end(), handshake.nonce);

        MessageHeader header = make_header(MessageType::HANDSHAKE_INIT, 0, sizeof(HandshakeMessage));
        std::vector<uint8_t> request_data = serialize_header(header);
        std::vector<uint8_t> handshake_payload = serialize_handshake(handshake);
        request_data.insert(request_data.end(), handshake_payload.begin(), handshake_payload.end());

        if (!send_data(request_data)) {
            return fail("Failed to send handshake init");
        }
        log("Sent handshake init");

        // Step 2: receive handshake response
        std::vector<uint8_t> response_data = receive_data();
        if (response_data.empty()) {
            return fail("No handshake response received");
        }
        if (response_data.size() < sizeof(MessageHeader)) {
            return fail("Handshake response too short");
        }

        MessageHeader response_header = deserialize_header(response_data);
        const std::string older = "The other side uses an older version of intercli; please update";
        if (response_header.type == MessageType::ERROR_MESSAGE && response_data.size() >= sizeof(MessageHeader) + 2) {
            ErrorCode code;
            std::memcpy(&code, response_data.data() + sizeof(MessageHeader), sizeof(code));
            if (code == ErrorCode::INVALID_PROTOCOL_VERSION) {
                return fail(older);
            }
        }
        if (response_header.version != PROTOCOL_VERSION) {
            return fail(older);
        }
        if (response_header.type != MessageType::HANDSHAKE_RESPONSE) {
            return fail("Expected HANDSHAKE_RESPONSE, got " + message_type_to_string(response_header.type));
        }

        std::vector<uint8_t> payload(response_data.begin() + sizeof(MessageHeader), response_data.end());
        if (payload.size() < sizeof(HandshakeMessage) + IDENTITY_KEY_SIZE + IDENTITY_SIGNATURE_SIZE) {
            return fail("Handshake response too short");
        }
        HandshakeMessage server_handshake = deserialize_handshake(payload);
        const auto proof = payload.begin() + sizeof(HandshakeMessage);
        const std::vector<uint8_t> identity(proof, proof + IDENTITY_KEY_SIZE);
        const std::vector<uint8_t> signature(proof + IDENTITY_KEY_SIZE,
                                             proof + IDENTITY_KEY_SIZE + IDENTITY_SIGNATURE_SIZE);
        log("Received handshake response from server");

        // The server owns the session identity. Adopt it, because the session id is
        // the salt for every later key rotation and both sides must derive the same key.
        session_.session_id = server_handshake.session_id;

        // Step 3: key exchange
        if (server_handshake.public_key_len == 0 || server_handshake.public_key_len > MAX_PUBLIC_KEY_SIZE) {
            return fail("Invalid server public key length");
        }
        std::vector<uint8_t> server_public_key(server_handshake.public_key,
                                               server_handshake.public_key + server_handshake.public_key_len);
        std::vector<uint8_t> shared_secret =
            crypto_->perform_dh_key_exchange(dh_keypair_.private_key, server_public_key);

        std::vector<uint8_t> server_nonce(server_handshake.nonce, server_handshake.nonce + IV_SIZE);

        // The server proves who it is: its identity key signed this exact
        // exchange. Checked before any key is used or anything else is sent.
        const std::vector<uint8_t> transcript =
            handshake_transcript(session_.session_id, dh_keypair_.public_key, nonce, server_public_key, server_nonce);
        if (!crypto_->identity_verify(identity, transcript, signature)) {
            return fail("The server could not prove its identity");
        }
        // Kept even when refused, so the app can show the new safety code.
        server_identity_ = identity;
        if (!expected_identity_.empty() && identity != expected_identity_) {
            return fail("This chat's identity has changed. If you didn't expect this, someone may be "
                        "intercepting the connection.");
        }

        std::vector<uint8_t> salt = nonce;
        salt.insert(salt.end(), server_nonce.begin(), server_nonce.end());
        SessionKeys keys = crypto_->derive_directional_keys(shared_secret, salt, false);
        {
            std::lock_guard<std::mutex> lock(send_mutex_);
            tx_key_ = keys.tx_key;
            tx_seq_ = 0;
        }
        {
            std::lock_guard<std::mutex> lock(rx_mutex_);
            rx_key_ = keys.rx_key;
            receive_rotations_ = 0;
        }
        rx_seq_ = 0;
        session_.shared_secret = shared_secret;
        session_.authenticated = true;
        log("Session key derived successfully");

        // Step 4: handshake complete
        MessageHeader complete_header = make_header(MessageType::HANDSHAKE_COMPLETE, 1, 0);
        if (!send_data(serialize_header(complete_header))) {
            return fail("Failed to send handshake complete");
        }
        log("Handshake completed successfully");
        return true;

    } catch (const std::exception& e) {
        return fail(std::string("Handshake error: ") + e.what());
    }
}

bool ChatClient::receive_all(uint8_t* data, size_t length) {
    const intptr_t s = socket_.load();
    if (s < 0) {
        return false;
    }
    size_t total = 0;
    while (total < length) {
        const int received = recv(static_cast<socket_t>(s), reinterpret_cast<char*>(data + total),
                                  static_cast<int>(length - total), 0);
        if (received <= 0) {
            return false;
        }
        total += static_cast<size_t>(received);
    }
    return true;
}

std::vector<uint8_t> ChatClient::receive_data() {
    uint32_t length_be = 0;
    if (!receive_all(reinterpret_cast<uint8_t*>(&length_be), sizeof(length_be))) {
        return {};
    }
    const uint32_t length = ntohl(length_be);
    if (length == 0 || length > MAX_FRAME_SIZE) {
        return {};
    }
    std::vector<uint8_t> buffer(length);
    if (!receive_all(buffer.data(), length)) {
        return {};
    }
    return buffer;
}

bool ChatClient::send_all(const uint8_t* data, size_t length) {
    const intptr_t s = socket_.load();
    if (s < 0) {
        return false;
    }
    size_t total = 0;
    while (total < length) {
        const int sent = send(static_cast<socket_t>(s), reinterpret_cast<const char*>(data + total),
                              static_cast<int>(length - total), 0);
        if (sent <= 0) {
            return false;
        }
        total += static_cast<size_t>(sent);
    }
    return true;
}

// Matches the server's 4-byte big-endian length framing.
bool ChatClient::send_data(const std::vector<uint8_t>& data) {
    const uint32_t length = htonl(static_cast<uint32_t>(data.size()));
    if (!send_all(reinterpret_cast<const uint8_t*>(&length), sizeof(length))) {
        return false;
    }
    return send_all(data.data(), data.size());
}

} // namespace SecureComm
