#include "chat_client.h"
#include "../../crypto/crypto_utils.h"

#include <algorithm>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
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

MessageHeader make_header(MessageType type, uint32_t sequence, uint16_t payload_size) {
    MessageHeader header{};
    header.version = ProtocolVersion::V1_0;
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

    try {
        if (client_keypair_.private_key.empty()) {
            client_keypair_ = crypto_->generate_rsa_keypair(2048);
            log("Client RSA key pair generated successfully");
        }
    } catch (const std::exception& e) {
        return fail(std::string("Key generation failed: ") + e.what());
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* results = nullptr;
    const std::string port_text = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_text.c_str(), &hints, &results) != 0 || !results) {
        return fail("Couldn't find the server " + host);
    }

    for (addrinfo* ai = results; ai; ai = ai->ai_next) {
        socket_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#ifdef _WIN32
        if (s == INVALID_SOCKET) continue;
#else
        if (s < 0) continue;
#endif
        if (::connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) {
            socket_ = static_cast<intptr_t>(s);
            break;
        }
        close_raw(static_cast<intptr_t>(s));
    }
    freeaddrinfo(results);

    if (socket_ < 0) {
        return fail("Couldn't connect to " + host + ":" + port_text);
    }

    log("Connected to server " + host + ":" + port_text);

    if (!perform_handshake(error)) {
        close_socket();
        return false;
    }

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

#ifdef INTERCLI_TESTING
void ChatClient::drop_connection_for_test() {
    const intptr_t s = socket_.load();
    if (s >= 0) {
        shutdown_raw(s);
    }
}
#endif

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

bool ChatClient::request_name(const std::string& name) {
    ChatMessage msg = make_chat(ChatType::REGISTER);
    set_chat_text(msg, name);
    return send_chat(msg);
}

bool ChatClient::send_direct(const std::string& to, const std::string& text) {
    if (text.size() > MAX_TEXT_LEN || to.empty() || to.size() >= MAX_NAME_LEN) {
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
            std::vector<uint8_t> message_data = serialize_chat(chat);
            std::vector<uint8_t> iv = crypto_->generate_random_bytes(IV_SIZE);
            std::vector<uint8_t> encrypted_data = crypto_->encrypt_aes_gcm(message_data, tx_key_, iv);
            if (encrypted_data.size() > MAX_MESSAGE_SIZE) {
                return false;
            }

            EncryptedMessage encrypted_msg{};
            encrypted_msg.session_id = session_.session_id;
            encrypted_msg.message_id = message_counter_;
            std::copy(iv.begin(), iv.begin() + std::min<size_t>(iv.size(), IV_SIZE), encrypted_msg.iv);
            std::copy(encrypted_data.begin(), encrypted_data.end(), encrypted_msg.encrypted_data);

            std::vector<uint8_t> signature = crypto_->sign_data(encrypted_data, client_keypair_.private_key);
            std::copy(signature.begin(), signature.begin() + std::min<size_t>(signature.size(), SIGNATURE_SIZE),
                      encrypted_msg.signature);

            MessageHeader header = make_header(MessageType::ENCRYPTED_MESSAGE, message_counter_,
                                               static_cast<uint16_t>(encrypted_data.size()));
            std::vector<uint8_t> request_data = serialize_header(header);
            std::vector<uint8_t> payload = serialize_encrypted_message(encrypted_msg);
            request_data.insert(request_data.end(), payload.begin(), payload.end());

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
        MessageHeader header = make_header(MessageType::KEY_ROTATION, message_counter_, 0);
        if (!send_data(serialize_header(header))) {
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
        // The server has rotated the direction it sends on.
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

    // payload_size comes off the wire; without this check it would read past
    // the end of encrypted_data.
    if (header.payload_size > MAX_MESSAGE_SIZE) {
        throw std::runtime_error("Encrypted payload size out of range");
    }

    std::vector<uint8_t> payload(data.begin() + sizeof(MessageHeader), data.end());
    EncryptedMessage msg = deserialize_encrypted_message(payload);

    std::vector<uint8_t> rx;
    {
        std::lock_guard<std::mutex> lock(rx_mutex_);
        rx = rx_key_;
    }

    std::vector<uint8_t> iv(msg.iv, msg.iv + IV_SIZE);
    std::vector<uint8_t> cipher(msg.encrypted_data, msg.encrypted_data + header.payload_size);
    std::vector<uint8_t> plain = crypto_->decrypt_aes_gcm(cipher, rx, iv);

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
        log(reason);
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

        // The long-lived RSA key signs messages; the key exchange needs an
        // ephemeral DH key of the same group as the server's.
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
        if (response_header.type != MessageType::HANDSHAKE_RESPONSE) {
            return fail("Expected HANDSHAKE_RESPONSE, got " + message_type_to_string(response_header.type));
        }

        std::vector<uint8_t> payload(response_data.begin() + sizeof(MessageHeader), response_data.end());
        HandshakeMessage server_handshake = deserialize_handshake(payload);
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
        SessionKeys keys = crypto_->derive_directional_keys(shared_secret, server_nonce, false);
        {
            std::lock_guard<std::mutex> lock(send_mutex_);
            tx_key_ = keys.tx_key;
        }
        {
            std::lock_guard<std::mutex> lock(rx_mutex_);
            rx_key_ = keys.rx_key;
            receive_rotations_ = 0;
        }
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
