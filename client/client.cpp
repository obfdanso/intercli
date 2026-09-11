#include "common.h"
#include "../crypto/crypto_utils.h"
#include <iostream>
#include <string>
#include <memory>
#include <algorithm>
#include <chrono>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

#include <cstring>

// using namespace SecureComm; // Removed to avoid namespace conflicts

class SecureClient {
private:
    int client_socket_;
    std::unique_ptr<SecureComm::CryptoManager> crypto_manager_;
    std::unique_ptr<SecureComm::SessionManager> session_manager_;
    std::unique_ptr<SecureComm::KeyManager> key_manager_;
    SecureComm::KeyPair client_keypair_;
    SecureComm::KeyPair dh_keypair_;
    SecureComm::SessionInfo current_session_;
    SecureComm::SessionKeys session_keys_;
    uint32_t message_counter_;
    std::mutex key_mutex_;
    std::thread receive_thread_;
    std::atomic<bool> connected_{false};
    std::mutex register_mutex_;
    std::condition_variable register_cv_;
    bool register_answered_ = false;
    bool register_ok_ = false;
    std::string my_name_;

public:
    SecureClient() : client_socket_(-1), message_counter_(0) {
#ifdef _WIN32
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif

        crypto_manager_ = std::make_unique<SecureComm::CryptoManager>();
        session_manager_ = std::make_unique<SecureComm::SessionManager>();
        key_manager_ = std::make_unique<SecureComm::KeyManager>();
        
        // Generate client's RSA key pair
        client_keypair_ = crypto_manager_->generate_rsa_keypair(2048);
        std::cout << "Client RSA key pair generated successfully" << std::endl;
    }

    ~SecureClient() {
        disconnect();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    bool connect(const std::string& server_ip, uint16_t port = SecureComm::DEFAULT_PORT) {
        client_socket_ = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
        if (client_socket_ < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
            std::cerr << "Invalid server address" << std::endl;
#ifdef _WIN32
            closesocket(client_socket_);
#else
            close(client_socket_);
#endif
            return false;
        }

                    if (::connect(client_socket_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Failed to connect to server" << std::endl;
#ifdef _WIN32
            closesocket(client_socket_);
#else
            close(client_socket_);
#endif
            return false;
        }

        std::cout << "Connected to server " << server_ip << ":" << port << std::endl;

        // Perform secure handshake
        if (!perform_handshake()) {
            std::cerr << "Handshake failed" << std::endl;
#ifdef _WIN32
            closesocket(client_socket_);
#else
            close(client_socket_);
#endif
            return false;
        }

        std::cout << "Secure connection established" << std::endl;

        connected_ = true;
        receive_thread_ = std::thread(&SecureClient::receive_loop, this);
        return true;
    }

    void disconnect() {
        connected_ = false;

        if (client_socket_ >= 0) {
            // Unblock the receive thread, which would otherwise sit in recv forever.
#ifdef _WIN32
            shutdown(client_socket_, SD_BOTH);
#else
            shutdown(client_socket_, SHUT_RDWR);
#endif
        }

        if (receive_thread_.joinable()) {
            receive_thread_.join();
        }

        if (client_socket_ >= 0) {
#ifdef _WIN32
            closesocket(client_socket_);
#else
            close(client_socket_);
#endif
            client_socket_ = -1;
        }
    }

    bool send_chat(const SecureComm::ChatMessage& chat) {
        try {
            std::vector<uint8_t> message_data = SecureComm::serialize_chat(chat);
            std::vector<uint8_t> iv = crypto_manager_->generate_random_bytes(SecureComm::IV_SIZE);

            std::vector<uint8_t> tx;
            {
                std::lock_guard<std::mutex> lock(key_mutex_);
                tx = session_keys_.tx_key;
            }
            std::vector<uint8_t> encrypted_data = crypto_manager_->encrypt_aes_gcm(message_data, tx, iv);

            SecureComm::EncryptedMessage encrypted_msg{};
            encrypted_msg.session_id = current_session_.session_id;
            encrypted_msg.message_id = message_counter_;
            
            // Copy IV
            size_t iv_copy_size = std::min<size_t>(iv.size(), SecureComm::IV_SIZE);
            std::copy(iv.begin(), iv.begin() + iv_copy_size, encrypted_msg.iv);
            
            // Copy encrypted data
            size_t data_copy_size = std::min<size_t>(encrypted_data.size(), SecureComm::MAX_MESSAGE_SIZE);
            std::copy(encrypted_data.begin(), encrypted_data.begin() + data_copy_size, encrypted_msg.encrypted_data);
            
            // Sign the encrypted data
            std::vector<uint8_t> signature = crypto_manager_->sign_data(encrypted_data, client_keypair_.private_key);
            size_t sig_copy_size = std::min<size_t>(signature.size(), SecureComm::SIGNATURE_SIZE);
            std::copy(signature.begin(), signature.begin() + sig_copy_size, encrypted_msg.signature);

            SecureComm::MessageHeader header;
            header.version = SecureComm::ProtocolVersion::V1_0;
            header.type = SecureComm::MessageType::ENCRYPTED_MESSAGE;
            header.sequence_number = message_counter_;
            header.timestamp = SecureComm::get_current_timestamp_seconds();
            header.payload_size = static_cast<uint16_t>(encrypted_data.size());
            header.flags = 0;

            std::vector<uint8_t> request_data = SecureComm::serialize_header(header);
            std::vector<uint8_t> msg_payload = SecureComm::serialize_encrypted_message(encrypted_msg);
            request_data.insert(request_data.end(), msg_payload.begin(), msg_payload.end());

            if (!send_data(request_data)) {
                std::cerr << "Failed to send encrypted message" << std::endl;
                return false;
            }

            message_counter_++;

            // Replies arrive on the receive thread, so there is nothing to wait for here.
            return true;

        } catch (const std::exception& e) {
            std::cerr << "Failed to send encrypted message: " << e.what() << std::endl;
            return false;
        }
    }

    // Input parsing is a client-side convenience that fills the structured fields.
    // A leading @ is the shorthand for a direct message; everything else broadcasts.
    bool send_line(const std::string& line) {
        if (line == "/who") {
            return send_chat(SecureComm::make_chat(SecureComm::ChatType::WHO));
        }

        if (line.rfind("@", 0) == 0) {
            const size_t space = line.find(' ');
            if (space == std::string::npos || space == 1) {
                std::cout << "Usage: @name message" << std::endl;
                return true;
            }
            SecureComm::ChatMessage msg = SecureComm::make_chat(SecureComm::ChatType::DIRECT);
            SecureComm::set_chat_field(msg.recipient, SecureComm::MAX_NAME_LEN,
                                       line.substr(1, space - 1));
            SecureComm::set_chat_text(msg, line.substr(space + 1));
            return send_chat(msg);
        }

        SecureComm::ChatMessage msg = SecureComm::make_chat(SecureComm::ChatType::BROADCAST);
        SecureComm::set_chat_text(msg, line);
        return send_chat(msg);
    }

    // Prompts until the server accepts a name. The reply arrives on the receive
    // thread, so the prompt waits on a condition variable rather than reading the
    // socket itself.
    bool register_name() {
        std::string name;
        while (connected_) {
            std::cout << "Enter your name: " << std::flush;
            if (!std::getline(std::cin, name)) {
                return false;
            }

            SecureComm::ChatMessage msg = SecureComm::make_chat(SecureComm::ChatType::REGISTER);
            SecureComm::set_chat_text(msg, name);
            if (!send_chat(msg)) {
                return false;
            }

            std::unique_lock<std::mutex> lock(register_mutex_);
            register_cv_.wait(lock, [this] { return register_answered_ || !connected_; });
            if (!connected_) {
                return false;
            }
            register_answered_ = false;
            if (register_ok_) {
                my_name_ = name;
                return true;
            }
        }
        return false;
    }

    // Announces that this peer is rotating the direction it sends on. The frame is
    // header-only, so it needs no key, and it goes out before the key changes. The
    // peer rotates its rx key when it reads the frame, so both switch at the same
    // point in the stream.
    bool rotate_tx_and_announce() {
        try {
            SecureComm::MessageHeader header{};
            header.version = SecureComm::ProtocolVersion::V1_0;
            header.type = SecureComm::MessageType::KEY_ROTATION;
            header.sequence_number = message_counter_;
            header.timestamp = SecureComm::get_current_timestamp_seconds();
            header.payload_size = 0;
            header.flags = 0;

            if (!send_data(SecureComm::serialize_header(header))) {
                std::cerr << "Failed to send key rotation marker" << std::endl;
                return false;
            }

            std::lock_guard<std::mutex> lock(key_mutex_);
            session_keys_.tx_key = crypto_manager_->rotate_session_key(
                session_keys_.tx_key, session_id_bytes());
            std::cout << "Rotated send key" << std::endl;
            return true;

        } catch (const std::exception& e) {
            std::cerr << "Key rotation failed: " << e.what() << std::endl;
            return false;
        }
    }

    void interactive_mode() {
        if (!register_name()) {
            std::cerr << "Registration failed" << std::endl;
            return;
        }

        std::cout << "\nInteractive mode"
                  << "\n  @name message  send a direct message"
                  << "\n  message        send to everyone"
                  << "\n  /who           list who is online"
                  << "\n  rotate         rotate your send key"
                  << "\n  quit           disconnect" << std::endl;
        std::string input;
        
        while (true) {
            std::cout << "> ";
            std::getline(std::cin, input);
            
            if (input == "quit" || input == "exit") {
                // Replies are asynchronous now, so give any still in flight a moment
                // to arrive before tearing the socket down.
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
                break;
            } else if (input == "rotate") {
                if (!rotate_tx_and_announce()) {
                    std::cerr << "Key rotation failed" << std::endl;
                }
            } else if (!input.empty()) {
                if (!send_line(input)) {
                    std::cerr << "Failed to send message" << std::endl;
                    break;
                }
            }
        }
    }

private:
    void print_incoming(const std::string& line) {
        // Redraw the prompt so an arriving message does not corrupt a half-typed line.
        std::cout << "\r" << line << std::endl << "> " << std::flush;
    }

    void handle_chat(const SecureComm::ChatMessage& msg) {
        if (msg.type == SecureComm::ChatType::REGISTER_OK ||
            msg.type == SecureComm::ChatType::REGISTER_FAIL) {
            const bool ok = (msg.type == SecureComm::ChatType::REGISTER_OK);
            if (ok) {
                std::cout << "Registered as " << SecureComm::get_chat_text(msg) << std::endl;
            } else {
                std::cout << SecureComm::get_chat_text(msg) << std::endl;
            }
            {
                std::lock_guard<std::mutex> lock(register_mutex_);
                register_ok_ = ok;
                register_answered_ = true;
            }
            register_cv_.notify_one();
            return;
        }

        const std::string from = SecureComm::get_chat_field(msg.sender, SecureComm::MAX_NAME_LEN);
        switch (msg.type) {
            case SecureComm::ChatType::DIRECT:
                print_incoming("[" + from + " -> you] " + SecureComm::get_chat_text(msg));
                break;
            case SecureComm::ChatType::BROADCAST:
                print_incoming("[" + from + "] " + SecureComm::get_chat_text(msg));
                break;
            case SecureComm::ChatType::NOTICE:
                print_incoming("*** " + SecureComm::get_chat_text(msg) + " ***");
                break;
            case SecureComm::ChatType::ROSTER:
                print_incoming(SecureComm::get_chat_text(msg));
                break;
            case SecureComm::ChatType::PRESENCE:
                print_incoming("*** " + SecureComm::get_chat_text(msg) + " ***");
                break;
            default:
                break;
        }
    }

    void dispatch_frame(const std::vector<uint8_t>& data) {
        SecureComm::MessageHeader header = SecureComm::deserialize_header(data);

        if (header.type == SecureComm::MessageType::KEY_ROTATION) {
            // The server has rotated the direction it sends on.
            std::lock_guard<std::mutex> lock(key_mutex_);
            session_keys_.rx_key = crypto_manager_->rotate_session_key(
                session_keys_.rx_key, session_id_bytes());
            return;
        }

        if (header.type == SecureComm::MessageType::ERROR_MESSAGE) {
            std::vector<uint8_t> payload(data.begin() + sizeof(SecureComm::MessageHeader), data.end());
            if (payload.size() >= sizeof(SecureComm::ErrorCode)) {
                SecureComm::ErrorCode code = *reinterpret_cast<const SecureComm::ErrorCode*>(payload.data());
                print_incoming(std::string("*** server error: ") +
                               SecureComm::error_code_to_string(code) + " ***");
            }
            return;
        }

        if (header.type != SecureComm::MessageType::ENCRYPTED_MESSAGE) {
            return;
        }

        std::vector<uint8_t> payload(data.begin() + sizeof(SecureComm::MessageHeader), data.end());
        SecureComm::EncryptedMessage msg = SecureComm::deserialize_encrypted_message(payload);

        std::vector<uint8_t> rx;
        {
            std::lock_guard<std::mutex> lock(key_mutex_);
            rx = session_keys_.rx_key;
        }

        std::vector<uint8_t> iv(msg.iv, msg.iv + SecureComm::IV_SIZE);
        std::vector<uint8_t> cipher(msg.encrypted_data, msg.encrypted_data + header.payload_size);
        std::vector<uint8_t> plain = crypto_manager_->decrypt_aes_gcm(cipher, rx, iv);

        handle_chat(SecureComm::deserialize_chat(plain));
    }

    void receive_loop() {
        while (connected_) {
            std::vector<uint8_t> data = receive_data();
            if (data.empty()) {
                if (connected_) {
                    connected_ = false;
                    print_incoming("*** disconnected from server ***");
                }
                register_cv_.notify_all();
                break;
            }
            try {
                dispatch_frame(data);
            } catch (const std::exception& e) {
                connected_ = false;
                print_incoming(std::string("*** receive error: ") + e.what() + " ***");
                register_cv_.notify_all();
                break;
            }
        }
    }

    std::vector<uint8_t> session_id_bytes() const {
        const uint32_t id = current_session_.session_id;
        return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&id),
                                    reinterpret_cast<const uint8_t*>(&id) + sizeof(id));
    }

    bool perform_handshake() {
        try {
            // Step 1: Send handshake init
            uint32_t client_id = SecureComm::generate_client_id();
            current_session_.client_id = client_id;
            current_session_.session_id = SecureComm::generate_session_id();

            SecureComm::HandshakeMessage handshake{};
            handshake.client_id = client_id;
            handshake.session_id = current_session_.session_id;
            handshake.fs_type = SecureComm::ForwardSecrecyType::PERFECT_FORWARD_SECRECY;
            
            // Copy client's ephemeral DH public key. The long-lived RSA key signs
            // messages; the key exchange needs a DH key of the same group as the server's.
            dh_keypair_ = crypto_manager_->generate_dh_keypair();

            if (dh_keypair_.public_key.size() > SecureComm::MAX_PUBLIC_KEY_SIZE) {
                std::cerr << "DH public key does not fit in handshake message" << std::endl;
                return false;
            }
            handshake.public_key_len = static_cast<uint16_t>(dh_keypair_.public_key.size());
            std::copy(dh_keypair_.public_key.begin(),
                     dh_keypair_.public_key.end(),
                     handshake.public_key);
            
            // Generate nonce
            std::vector<uint8_t> nonce = SecureComm::generate_nonce(SecureComm::IV_SIZE);
            std::copy(nonce.begin(), nonce.end(), handshake.nonce);

            SecureComm::MessageHeader header;
            header.version = SecureComm::ProtocolVersion::V1_0;
            header.type = SecureComm::MessageType::HANDSHAKE_INIT;
            header.sequence_number = 0;
            header.timestamp = SecureComm::get_current_timestamp_seconds();
            header.payload_size = sizeof(SecureComm::HandshakeMessage);
            header.flags = 0;

            std::vector<uint8_t> request_data = SecureComm::serialize_header(header);
            std::vector<uint8_t> handshake_payload = SecureComm::serialize_handshake(handshake);
            request_data.insert(request_data.end(), handshake_payload.begin(), handshake_payload.end());

            if (!send_data(request_data)) {
                std::cerr << "Failed to send handshake init" << std::endl;
                return false;
            }

            std::cout << "Sent handshake init" << std::endl;

            // Step 2: Receive handshake response
            std::vector<uint8_t> response_data = receive_data();
            if (response_data.empty()) {
                std::cerr << "No handshake response received" << std::endl;
                return false;
            }

            SecureComm::MessageHeader response_header = SecureComm::deserialize_header(response_data);
            if (response_header.type != SecureComm::MessageType::HANDSHAKE_RESPONSE) {
                std::cerr << "Expected HANDSHAKE_RESPONSE, got " << SecureComm::message_type_to_string(response_header.type) << std::endl;
                return false;
            }

            // Extract server handshake
            std::vector<uint8_t> payload(response_data.begin() + sizeof(SecureComm::MessageHeader), response_data.end());
            SecureComm::HandshakeMessage server_handshake = SecureComm::deserialize_handshake(payload);

            std::cout << "Received handshake response from server" << std::endl;

            // The server owns the session identity. Adopt it, because the session id is
            // the salt for every later key rotation and both sides must derive the same key.
            current_session_.session_id = server_handshake.session_id;

            // Step 3: Perform key exchange
            if (server_handshake.public_key_len == 0 ||
                server_handshake.public_key_len > SecureComm::MAX_PUBLIC_KEY_SIZE) {
                std::cerr << "Invalid server public key length" << std::endl;
                return false;
            }

            std::vector<uint8_t> server_public_key(server_handshake.public_key,
                                                  server_handshake.public_key + server_handshake.public_key_len);
            
            std::vector<uint8_t> shared_secret = crypto_manager_->perform_dh_key_exchange(
                dh_keypair_.private_key, server_public_key);
            
            // Derive session keys
            std::vector<uint8_t> server_nonce(server_handshake.nonce, server_handshake.nonce + SecureComm::IV_SIZE);
            session_keys_ = crypto_manager_->derive_directional_keys(shared_secret, server_nonce, false);

            current_session_.shared_secret = shared_secret;
            current_session_.tx_key = session_keys_.tx_key;
            current_session_.rx_key = session_keys_.rx_key;
            current_session_.authenticated = true;

            std::cout << "Session key derived successfully" << std::endl;

            // Step 4: Send handshake complete
            SecureComm::MessageHeader complete_header;
            complete_header.version = SecureComm::ProtocolVersion::V1_0;
            complete_header.type = SecureComm::MessageType::HANDSHAKE_COMPLETE;
            complete_header.sequence_number = 1;
            complete_header.timestamp = SecureComm::get_current_timestamp_seconds();
            complete_header.payload_size = 0;
            complete_header.flags = 0;

            std::vector<uint8_t> complete_data = SecureComm::serialize_header(complete_header);
            
            if (!send_data(complete_data)) {
                std::cerr << "Failed to send handshake complete" << std::endl;
                return false;
            }

            std::cout << "Handshake completed successfully" << std::endl;
            return true;

        } catch (const std::exception& e) {
            std::cerr << "Handshake error: " << e.what() << std::endl;
            return false;
        }
    }


    bool receive_all(uint8_t* data, size_t length) {
        size_t total = 0;
        while (total < length) {
            int received = recv(client_socket_, reinterpret_cast<char*>(data + total),
                                static_cast<int>(length - total), 0);
            if (received <= 0) {
                return false;
            }
            total += static_cast<size_t>(received);
        }
        return true;
    }

    std::vector<uint8_t> receive_data() {
        uint32_t length_be = 0;
        if (!receive_all(reinterpret_cast<uint8_t*>(&length_be), sizeof(length_be))) {
            return std::vector<uint8_t>();
        }

        uint32_t length = ntohl(length_be);
        if (length == 0 || length > SecureComm::MAX_FRAME_SIZE) {
            return std::vector<uint8_t>();
        }

        std::vector<uint8_t> buffer(length);
        if (!receive_all(buffer.data(), length)) {
            return std::vector<uint8_t>();
        }
        return buffer;
    }

    bool send_all(const uint8_t* data, size_t length) {
        size_t total = 0;
        while (total < length) {
            int sent = send(client_socket_, reinterpret_cast<const char*>(data + total),
                            static_cast<int>(length - total), 0);
            if (sent <= 0) {
                return false;
            }
            total += static_cast<size_t>(sent);
        }
        return true;
    }

    // Matches the server's 4-byte big-endian length framing.
    bool send_data(const std::vector<uint8_t>& data) {
        uint32_t length = htonl(static_cast<uint32_t>(data.size()));
        if (!send_all(reinterpret_cast<const uint8_t*>(&length), sizeof(length))) {
            return false;
        }
        return send_all(data.data(), data.size());
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <server_ip> [port]" << std::endl;
        std::cout << "Example: " << argv[0] << " 127.0.0.1 8080" << std::endl;
        return 1;
    }

    std::string server_ip = argv[1];
    uint16_t port = (argc > 2) ? static_cast<uint16_t>(std::stoi(argv[2])) : SecureComm::DEFAULT_PORT;

    try {
        SecureClient client;
        
        if (!client.connect(server_ip, port)) {
            std::cerr << "Failed to connect to server" << std::endl;
            return 1;
        }

        std::cout << "Secure Communication Client" << std::endl;
        std::cout << "Features:" << std::endl;
        std::cout << "- RSA-2048 key exchange" << std::endl;
        std::cout << "- AES-256-GCM encryption" << std::endl;
        std::cout << "- Perfect Forward Secrecy with DH key exchange" << std::endl;
        std::cout << "- Session authentication" << std::endl;
        std::cout << "- Manual key rotation" << std::endl;
        std::cout << "- Digital signatures" << std::endl;

        // Start interactive mode
        client.interactive_mode();

    } catch (const std::exception& e) {
        std::cerr << "Client error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
} 