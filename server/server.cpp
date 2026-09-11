#include "common.h"
#include "../crypto/crypto_utils.h"
#include <iostream>
#include <thread>
#include <vector>
#include <memory>
#include <atomic>
#include <algorithm>
#include <chrono>

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
#include <signal.h>
#include <map>
#include <mutex>
#include <string>

// One connected client. Held by shared_ptr because a relaying thread may be
// mid-send to a client that is disconnecting; the object outlives the registry
// entry until the last reference drops, and alive makes late sends no-ops.
struct ClientConnection {
    int               socket = -1;
    uint32_t          session_id = 0;
    std::string       name;
    std::mutex        send_mutex;
    std::atomic<bool> alive{true};
};

// using namespace SecureComm; // Removed to avoid namespace conflicts

class SecureServer {
private:
    int server_socket_;
    std::atomic<bool> running_;
    std::unique_ptr<SecureComm::CryptoManager> crypto_manager_;
    std::unique_ptr<SecureComm::SessionManager> session_manager_;
    std::unique_ptr<SecureComm::KeyManager> key_manager_;
    std::vector<std::thread> client_threads_;
    std::map<std::string, std::shared_ptr<ClientConnection>> registry_;
    std::mutex registry_mutex_;
    SecureComm::KeyPair server_keypair_;

public:
    SecureServer() : server_socket_(-1), running_(false) {
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
        
        // Generate server's RSA key pair
        server_keypair_ = crypto_manager_->generate_rsa_keypair(2048);
        std::cout << "Server RSA key pair generated successfully" << std::endl;
    }

    ~SecureServer() {
        stop();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    bool start(uint16_t port = SecureComm::DEFAULT_PORT) {
        server_socket_ = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
        if (server_socket_ < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }

        int opt = 1;
        if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt)) < 0) {
            std::cerr << "Failed to set socket options" << std::endl;
#ifdef _WIN32
            closesocket(server_socket_);
#else
            close(server_socket_);
#endif
            return false;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (bind(server_socket_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Failed to bind socket" << std::endl;
#ifdef _WIN32
            closesocket(server_socket_);
#else
            close(server_socket_);
#endif
            return false;
        }

        if (listen(server_socket_, 10) < 0) {
            std::cerr << "Failed to listen on socket" << std::endl;
#ifdef _WIN32
            closesocket(server_socket_);
#else
            close(server_socket_);
#endif
            return false;
        }

        running_ = true;
        std::cout << "Secure server started on port " << port << std::endl;
        std::cout << "Server public key: " << SecureComm::bytes_to_hex(server_keypair_.public_key).substr(0, 64) << "..." << std::endl;

        // Start cleanup thread
        std::thread cleanup_thread([this]() {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::minutes(5));
                session_manager_->cleanup_expired_sessions();
            }
        });
        cleanup_thread.detach();

        return true;
    }

    void run() {
        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_socket = static_cast<int>(accept(server_socket_, (struct sockaddr*)&client_addr, &client_len));
            if (client_socket < 0) {
                if (running_) {
                    std::cerr << "Failed to accept client connection" << std::endl;
                }
                continue;
            }

            std::cout << "New client connected from " << inet_ntoa(client_addr.sin_addr) 
                      << ":" << ntohs(client_addr.sin_port) << std::endl;

            // Handle client in separate thread
            client_threads_.emplace_back(&SecureServer::handle_client, this, client_socket);
        }
    }

    void stop() {
        running_ = false;
        
        if (server_socket_ >= 0) {
#ifdef _WIN32
            closesocket(server_socket_);
#else
            close(server_socket_);
#endif
            server_socket_ = -1;
        }

        // Wait for all client threads to finish
        for (auto& thread : client_threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        client_threads_.clear();
    }

private:
    void handle_client(int client_socket) {
        auto conn = std::make_shared<ClientConnection>();
        conn->socket = client_socket;

        try {
            uint32_t client_id = SecureComm::generate_client_id();
            SecureComm::SessionInfo session = session_manager_->create_session(client_id);
            conn->session_id = session.session_id;

            std::cout << "Created session " << session.session_id << " for client " << client_id << std::endl;

            // Perform secure handshake
            if (!perform_handshake(client_socket, session)) {
                std::cerr << "Handshake failed for client " << client_id << std::endl;
#ifdef _WIN32
                closesocket(client_socket);
#else
                close(client_socket);
#endif
                return;
            }

            std::cout << "Handshake completed successfully for client " << client_id << std::endl;

            // Handle encrypted messages
            handle_encrypted_messages(conn, session);

        } catch (const std::exception& e) {
            std::cerr << "Error handling client: " << e.what() << std::endl;
        }

        conn->alive = false;
        const std::string departed = conn->name;
        unregister(conn);
        if (!departed.empty()) {
            broadcast_presence(departed, false, std::string());
        }

#ifdef _WIN32
        closesocket(client_socket);
#else
        close(client_socket);
#endif
        std::cout << "Client disconnected" << std::endl;
    }

    bool perform_handshake(int client_socket, SecureComm::SessionInfo& session) {
        try {
            // Step 1: Receive handshake init
            std::vector<uint8_t> handshake_data = receive_data(client_socket);
            SecureComm::MessageHeader header = SecureComm::deserialize_header(handshake_data);
            
            if (header.type != SecureComm::MessageType::HANDSHAKE_INIT) {
                std::cerr << "Expected HANDSHAKE_INIT, got " << SecureComm::message_type_to_string(header.type) << std::endl;
                return false;
            }

            // Extract handshake message
            std::vector<uint8_t> payload(handshake_data.begin() + sizeof(SecureComm::MessageHeader), handshake_data.end());
            SecureComm::HandshakeMessage client_handshake = SecureComm::deserialize_handshake(payload);

            std::cout << "Received handshake init from client " << client_handshake.client_id << std::endl;

            // Step 2: Generate DH key pair for forward secrecy
            SecureComm::KeyPair dh_keypair = crypto_manager_->generate_dh_keypair();
            
            // Step 3: Perform key exchange
            if (client_handshake.public_key_len == 0 ||
                client_handshake.public_key_len > SecureComm::MAX_PUBLIC_KEY_SIZE) {
                std::cerr << "Invalid client public key length" << std::endl;
                return false;
            }

            std::vector<uint8_t> client_public_key_vec(client_handshake.public_key, client_handshake.public_key + client_handshake.public_key_len);
            std::vector<uint8_t> shared_secret = crypto_manager_->perform_dh_key_exchange(
                dh_keypair.private_key, client_public_key_vec);
            
            // Derive session key
            std::vector<uint8_t> client_nonce_vec(client_handshake.nonce, client_handshake.nonce + SecureComm::IV_SIZE);
            SecureComm::SessionKeys keys = crypto_manager_->derive_directional_keys(
                shared_secret, client_nonce_vec, true);

            // Store session keys
            session_manager_->set_session_keys(session.session_id, keys);
            session.shared_secret = shared_secret;
            session.tx_key = keys.tx_key;
            session.rx_key = keys.rx_key;

            // Step 4: Send handshake response
            SecureComm::HandshakeMessage server_handshake{};
            server_handshake.client_id = session.client_id;
            server_handshake.session_id = session.session_id;
            server_handshake.fs_type = SecureComm::ForwardSecrecyType::PERFECT_FORWARD_SECRECY;

            // Copy DH public key
            if (dh_keypair.public_key.size() > SecureComm::MAX_PUBLIC_KEY_SIZE) {
                std::cerr << "DH public key does not fit in handshake message" << std::endl;
                return false;
            }
            server_handshake.public_key_len = static_cast<uint16_t>(dh_keypair.public_key.size());
            std::copy(dh_keypair.public_key.begin(), dh_keypair.public_key.end(), server_handshake.public_key);
            
            // Copy nonce
            std::copy(client_handshake.nonce, client_handshake.nonce + SecureComm::IV_SIZE, server_handshake.nonce);

            SecureComm::MessageHeader response_header;
            response_header.version = SecureComm::ProtocolVersion::V1_0;
            response_header.type = SecureComm::MessageType::HANDSHAKE_RESPONSE;
            response_header.sequence_number = 1;
            response_header.timestamp = SecureComm::get_current_timestamp_seconds();
            response_header.payload_size = sizeof(SecureComm::HandshakeMessage);
            response_header.flags = 0;

            std::vector<uint8_t> response_data = SecureComm::serialize_header(response_header);
            std::vector<uint8_t> handshake_payload = SecureComm::serialize_handshake(server_handshake);
            response_data.insert(response_data.end(), handshake_payload.begin(), handshake_payload.end());

            if (!send_data(client_socket, response_data)) {
                std::cerr << "Failed to send handshake response" << std::endl;
                return false;
            }

            // Step 5: Receive handshake complete
            std::vector<uint8_t> complete_data = receive_data(client_socket);
            SecureComm::MessageHeader complete_header = SecureComm::deserialize_header(complete_data);
            
            if (complete_header.type != SecureComm::MessageType::HANDSHAKE_COMPLETE) {
                std::cerr << "Expected HANDSHAKE_COMPLETE, got " << SecureComm::message_type_to_string(complete_header.type) << std::endl;
                return false;
            }

            // Authenticate session
            session_manager_->authenticate_session(session.session_id, std::vector<uint8_t>());
            session.authenticated = true;

            std::cout << "Handshake completed for session " << session.session_id << std::endl;
            return true;

        } catch (const std::exception& e) {
            std::cerr << "Handshake error: " << e.what() << std::endl;
            return false;
        }
    }

    void handle_encrypted_messages(const std::shared_ptr<ClientConnection>& conn,
                                   SecureComm::SessionInfo& session) {
        const int client_socket = conn->socket;
        uint32_t message_counter = 0;

        while (running_) {
            try {
                std::vector<uint8_t> encrypted_data = receive_data(client_socket);
                if (encrypted_data.empty()) {
                    break; // Client disconnected
                }

                SecureComm::MessageHeader header = SecureComm::deserialize_header(encrypted_data);
                
                if (header.type == SecureComm::MessageType::ENCRYPTED_MESSAGE) {
                    // Extract encrypted message
                    std::vector<uint8_t> payload(encrypted_data.begin() + sizeof(SecureComm::MessageHeader), encrypted_data.end());
                    SecureComm::EncryptedMessage encrypted_msg = SecureComm::deserialize_encrypted_message(payload);

                    // Verify session
                    SecureComm::AuthResult auth_result = session_manager_->verify_session_auth(session.session_id, 
                                                                                  std::vector<uint8_t>(encrypted_msg.signature, 
                                                                                                      encrypted_msg.signature + SecureComm::SIGNATURE_SIZE));
                    if (auth_result != SecureComm::AuthResult::SUCCESS) {
                        std::cerr << "Authentication failed: " << static_cast<int>(auth_result) << std::endl;
                        send_error(client_socket, SecureComm::ErrorCode::AUTHENTICATION_FAILED);
                        break;
                    }

                    // Decrypt message
                    std::vector<uint8_t> key = session_manager_->get_rx_key(session.session_id);
                    std::vector<uint8_t> iv(encrypted_msg.iv, encrypted_msg.iv + SecureComm::IV_SIZE);
                    
                    std::vector<uint8_t> decrypted_data = crypto_manager_->decrypt_aes_gcm(
                        std::vector<uint8_t>(encrypted_msg.encrypted_data, 
                                           encrypted_msg.encrypted_data + header.payload_size),
                        key, iv);

                    SecureComm::ChatMessage chat = SecureComm::deserialize_chat(decrypted_data);

                    if (chat.type == SecureComm::ChatType::REGISTER) {
                        const std::string wanted = SecureComm::get_chat_text(chat);
                        std::string reason;
                        if (!SecureComm::is_valid_name(wanted)) {
                            reason = "Name must be 1-31 printable characters with no spaces";
                        } else if (!conn->name.empty()) {
                            reason = "Already registered as " + conn->name;
                        } else if (!register_name(wanted, conn)) {
                            reason = "That name is taken";
                        }

                        SecureComm::ChatMessage reply = SecureComm::make_chat(
                            reason.empty() ? SecureComm::ChatType::REGISTER_OK
                                           : SecureComm::ChatType::REGISTER_FAIL);
                        SecureComm::set_chat_text(reply, reason.empty() ? wanted : reason);
                        send_chat(conn, reply);

                        if (reason.empty()) {
                            std::cout << "Registered " << wanted << " on session "
                                      << session.session_id << std::endl;
                            broadcast_presence(wanted, true, wanted);
                        }
                        message_counter++;
                        continue;
                    }

                    if (conn->name.empty()) {
                        send_notice(conn, "Register a name before sending messages");
                        message_counter++;
                        continue;
                    }

                    if (chat.type == SecureComm::ChatType::DIRECT) {
                        const std::string to =
                            SecureComm::get_chat_field(chat.recipient, SecureComm::MAX_NAME_LEN);
                        std::shared_ptr<ClientConnection> target = lookup(to);
                        if (!target) {
                            send_notice(conn, "No such user: " + to);
                            message_counter++;
                            continue;
                        }

                        // sender is stamped from the registry, never from the inbound
                        // envelope, so a client cannot claim to be someone else.
                        SecureComm::ChatMessage out =
                            SecureComm::make_chat(SecureComm::ChatType::DIRECT);
                        SecureComm::set_chat_field(out.sender, SecureComm::MAX_NAME_LEN, conn->name);
                        SecureComm::set_chat_field(out.recipient, SecureComm::MAX_NAME_LEN, to);
                        SecureComm::set_chat_text(out, SecureComm::get_chat_text(chat));
                        send_chat(target, out);

                        std::cout << conn->name << " -> " << to << ": "
                                  << SecureComm::get_chat_text(chat) << std::endl;
                        message_counter++;
                        continue;
                    }

                    if (chat.type == SecureComm::ChatType::BROADCAST) {
                        SecureComm::ChatMessage out =
                            SecureComm::make_chat(SecureComm::ChatType::BROADCAST);
                        SecureComm::set_chat_field(out.sender, SecureComm::MAX_NAME_LEN, conn->name);
                        SecureComm::set_chat_text(out, SecureComm::get_chat_text(chat));

                        for (const auto& peer : roster_snapshot()) {
                            if (peer->name != conn->name) {
                                send_chat(peer, out);
                            }
                        }

                        std::cout << conn->name << " (all): "
                                  << SecureComm::get_chat_text(chat) << std::endl;
                        message_counter++;
                        continue;
                    }

                    if (chat.type == SecureComm::ChatType::WHO) {
                        std::string names;
                        size_t count = 0;
                        for (const auto& peer : roster_snapshot()) {
                            if (!names.empty()) {
                                names += ", ";
                            }
                            names += peer->name;
                            ++count;
                        }
                        SecureComm::ChatMessage reply =
                            SecureComm::make_chat(SecureComm::ChatType::ROSTER);
                        SecureComm::set_chat_text(
                            reply, "Online (" + std::to_string(count) + "): " + names);
                        send_chat(conn, reply);
                        message_counter++;
                        continue;
                    }

                    send_notice(conn, "Unsupported message type");
                    message_counter++;

                    // Rotate the direction this peer sends on, every 10 messages.
                    if (message_counter % 10 == 0) {
                        rotate_tx_and_announce(client_socket, session.session_id);
                        std::cout << "Rotated send key for session " << session.session_id << std::endl;
                    }

                } else if (header.type == SecureComm::MessageType::KEY_ROTATION) {
                    // The client has rotated the direction it sends on.
                    session_manager_->rotate_rx_key(session.session_id);
                    std::cout << "Client rotated its send key for session " << session.session_id << std::endl;

                } else if (header.type == SecureComm::MessageType::ERROR_MESSAGE) {
                    std::cerr << "Received error message from client" << std::endl;
                    break;

                } else {
                    std::cerr << "Unknown message type: " << static_cast<int>(header.type) << std::endl;
                    send_error(client_socket, SecureComm::ErrorCode::INVALID_MESSAGE);
                }

            } catch (const std::exception& e) {
                std::cerr << "Error handling encrypted message: " << e.what() << std::endl;
                send_error(client_socket, SecureComm::ErrorCode::INTERNAL_ERROR);
                break;
            }
        }
    }

    void send_encrypted_message(int client_socket, const SecureComm::SessionInfo& session, const std::string& message) {
        try {
            // The payload is a ChatMessage envelope, which the client decodes by type.
            SecureComm::ChatMessage chat = SecureComm::make_chat(SecureComm::ChatType::NOTICE);
            SecureComm::set_chat_text(chat, message);
            std::vector<uint8_t> message_data = SecureComm::serialize_chat(chat);

            std::vector<uint8_t> key = session_manager_->get_tx_key(session.session_id);
            std::vector<uint8_t> iv = crypto_manager_->generate_random_bytes(SecureComm::IV_SIZE);
            
            std::vector<uint8_t> encrypted_data = crypto_manager_->encrypt_aes_gcm(message_data, key, iv);
            
            SecureComm::EncryptedMessage encrypted_msg{};
            encrypted_msg.session_id = session.session_id;
            encrypted_msg.message_id = session.message_counter;
            
            // Copy IV
            size_t iv_copy_size = std::min<size_t>(iv.size(), SecureComm::IV_SIZE);
            std::copy(iv.begin(), iv.begin() + iv_copy_size, encrypted_msg.iv);
            
            // Copy encrypted data
            size_t data_copy_size = std::min<size_t>(encrypted_data.size(), SecureComm::MAX_MESSAGE_SIZE);
            std::copy(encrypted_data.begin(), encrypted_data.begin() + data_copy_size, encrypted_msg.encrypted_data);
            
            // Sign the encrypted data
            std::vector<uint8_t> signature = crypto_manager_->sign_data(encrypted_data, server_keypair_.private_key);
            size_t sig_copy_size = std::min<size_t>(signature.size(), SecureComm::SIGNATURE_SIZE);
            std::copy(signature.begin(), signature.begin() + sig_copy_size, encrypted_msg.signature);

            SecureComm::MessageHeader header;
            header.version = SecureComm::ProtocolVersion::V1_0;
            header.type = SecureComm::MessageType::ENCRYPTED_MESSAGE;
            header.sequence_number = session.message_counter;
            header.timestamp = SecureComm::get_current_timestamp_seconds();
            header.payload_size = static_cast<uint16_t>(encrypted_data.size());
            header.flags = 0;

            std::vector<uint8_t> response_data = SecureComm::serialize_header(header);
            std::vector<uint8_t> msg_payload = SecureComm::serialize_encrypted_message(encrypted_msg);
            response_data.insert(response_data.end(), msg_payload.begin(), msg_payload.end());

            send_data(client_socket, response_data);

        } catch (const std::exception& e) {
            std::cerr << "Failed to send encrypted message: " << e.what() << std::endl;
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
    void send_chat(const std::shared_ptr<ClientConnection>& conn, const SecureComm::ChatMessage& msg) {
        if (!conn->alive) {
            return;
        }
        std::lock_guard<std::mutex> lock(conn->send_mutex);
        try {
            std::vector<uint8_t> tx = session_manager_->get_tx_key(conn->session_id);
            std::vector<uint8_t> iv = crypto_manager_->generate_random_bytes(SecureComm::IV_SIZE);
            std::vector<uint8_t> cipher =
                crypto_manager_->encrypt_aes_gcm(SecureComm::serialize_chat(msg), tx, iv);

            if (cipher.size() > SecureComm::MAX_MESSAGE_SIZE) {
                return;
            }

            SecureComm::EncryptedMessage out{};
            out.session_id = conn->session_id;
            out.message_id = 0;
            std::copy(iv.begin(), iv.end(), out.iv);
            std::copy(cipher.begin(), cipher.end(), out.encrypted_data);

            std::vector<uint8_t> signature =
                crypto_manager_->sign_data(cipher, server_keypair_.private_key);
            const size_t sig_len = std::min<size_t>(signature.size(), SecureComm::SIGNATURE_SIZE);
            std::copy(signature.begin(), signature.begin() + sig_len, out.signature);

            SecureComm::MessageHeader header{};
            header.version = SecureComm::ProtocolVersion::V1_0;
            header.type = SecureComm::MessageType::ENCRYPTED_MESSAGE;
            header.sequence_number = 0;
            header.timestamp = SecureComm::get_current_timestamp_seconds();
            header.payload_size = static_cast<uint16_t>(cipher.size());
            header.flags = 0;

            std::vector<uint8_t> frame = SecureComm::serialize_header(header);
            std::vector<uint8_t> body = SecureComm::serialize_encrypted_message(out);
            frame.insert(frame.end(), body.begin(), body.end());

            if (!send_data(conn->socket, frame)) {
                conn->alive = false;
            }
        } catch (const std::exception&) {
            conn->alive = false;
        }
    }

    void broadcast_presence(const std::string& name, bool joined, const std::string& except) {
        SecureComm::ChatMessage msg = SecureComm::make_chat(SecureComm::ChatType::PRESENCE);
        SecureComm::set_chat_field(msg.sender, SecureComm::MAX_NAME_LEN, name);
        SecureComm::set_chat_text(msg, name + (joined ? " joined" : " left"));

        for (const auto& peer : roster_snapshot()) {
            if (peer->name != except) {
                send_chat(peer, msg);
            }
        }
    }

    void send_notice(const std::shared_ptr<ClientConnection>& conn, const std::string& text) {
        SecureComm::ChatMessage msg = SecureComm::make_chat(SecureComm::ChatType::NOTICE);
        SecureComm::set_chat_text(msg, text);
        send_chat(conn, msg);
    }

    // Announces that this peer is rotating the direction it sends on. The frame is
    // header-only, so it needs no key, and it goes out before the key changes. The
    // peer rotates its rx key when it reads the frame, so both switch at the same
    // point in the stream and neither direction disturbs the other.
    bool rotate_tx_and_announce(int client_socket, uint32_t session_id) {
        SecureComm::MessageHeader header{};
        header.version = SecureComm::ProtocolVersion::V1_0;
        header.type = SecureComm::MessageType::KEY_ROTATION;
        header.sequence_number = 0;
        header.timestamp = SecureComm::get_current_timestamp_seconds();
        header.payload_size = 0;
        header.flags = 0;

        if (!send_data(client_socket, SecureComm::serialize_header(header))) {
            return false;
        }
        session_manager_->rotate_tx_key(session_id);
        return true;
    }

    void send_error(int client_socket, SecureComm::ErrorCode error_code) {
        SecureComm::MessageHeader header;
        header.version = SecureComm::ProtocolVersion::V1_0;
        header.type = SecureComm::MessageType::ERROR_MESSAGE;
        header.sequence_number = 0;
        header.timestamp = SecureComm::get_current_timestamp_seconds();
        header.payload_size = sizeof(SecureComm::ErrorCode);
        header.flags = 0;

        std::vector<uint8_t> response_data = SecureComm::serialize_header(header);
        std::vector<uint8_t> error_data(reinterpret_cast<const uint8_t*>(&error_code), 
                                       reinterpret_cast<const uint8_t*>(&error_code) + sizeof(SecureComm::ErrorCode));
        response_data.insert(response_data.end(), error_data.begin(), error_data.end());

        send_data(client_socket, response_data);
    }

    bool receive_all(int client_socket, uint8_t* data, size_t length) {
        size_t total = 0;
        while (total < length) {
            int received = recv(client_socket, reinterpret_cast<char*>(data + total),
                                static_cast<int>(length - total), 0);
            if (received <= 0) {
                return false;
            }
            total += static_cast<size_t>(received);
        }
        return true;
    }

    std::vector<uint8_t> receive_data(int client_socket) {
        uint32_t length_be = 0;
        if (!receive_all(client_socket, reinterpret_cast<uint8_t*>(&length_be), sizeof(length_be))) {
            return std::vector<uint8_t>();
        }

        uint32_t length = ntohl(length_be);
        if (length == 0 || length > SecureComm::MAX_FRAME_SIZE) {
            return std::vector<uint8_t>();
        }

        std::vector<uint8_t> buffer(length);
        if (!receive_all(client_socket, buffer.data(), length)) {
            return std::vector<uint8_t>();
        }
        return buffer;
    }

    bool send_all(int client_socket, const uint8_t* data, size_t length) {
        size_t total = 0;
        while (total < length) {
            int sent = send(client_socket, reinterpret_cast<const char*>(data + total),
                            static_cast<int>(length - total), 0);
            if (sent <= 0) {
                return false;
            }
            total += static_cast<size_t>(sent);
        }
        return true;
    }

    // Every message is framed with a 4-byte big-endian length so that a message
    // larger than one recv() buffer, or split across TCP segments, still arrives whole.
    bool send_data(int client_socket, const std::vector<uint8_t>& data) {
        uint32_t length = htonl(static_cast<uint32_t>(data.size()));
        if (!send_all(client_socket, reinterpret_cast<const uint8_t*>(&length), sizeof(length))) {
            return false;
        }
        return send_all(client_socket, data.data(), data.size());
    }
};

std::atomic<bool> g_running(true);

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nReceived signal " << signal << ", shutting down..." << std::endl;
        g_running = false;
    }
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    try {
        SecureServer server;
        
        if (!server.start(SecureComm::DEFAULT_PORT)) {
            std::cerr << "Failed to start server" << std::endl;
            return 1;
        }

        std::cout << "Secure Communication Server" << std::endl;
        std::cout << "Features:" << std::endl;
        std::cout << "- RSA-2048 key exchange" << std::endl;
        std::cout << "- AES-256-GCM encryption" << std::endl;
        std::cout << "- Perfect Forward Secrecy with DH key exchange" << std::endl;
        std::cout << "- Session authentication" << std::endl;
        std::cout << "- Automatic key rotation" << std::endl;
        std::cout << "- Digital signatures" << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;

        server.run();

    } catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
} 