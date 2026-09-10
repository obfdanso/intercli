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

// using namespace SecureComm; // Removed to avoid namespace conflicts

class SecureServer {
private:
    int server_socket_;
    std::atomic<bool> running_;
    std::unique_ptr<SecureComm::CryptoManager> crypto_manager_;
    std::unique_ptr<SecureComm::SessionManager> session_manager_;
    std::unique_ptr<SecureComm::KeyManager> key_manager_;
    std::vector<std::thread> client_threads_;
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
        try {
            uint32_t client_id = SecureComm::generate_client_id();
            SecureComm::SessionInfo session = session_manager_->create_session(client_id);
            
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
            handle_encrypted_messages(client_socket, session);

        } catch (const std::exception& e) {
            std::cerr << "Error handling client: " << e.what() << std::endl;
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

    void handle_encrypted_messages(int client_socket, SecureComm::SessionInfo& session) {
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

                    // Process message
                    std::string message(decrypted_data.begin(), decrypted_data.end());
                    std::cout << "Received encrypted message from client " << session.client_id 
                              << ": " << message << std::endl;

                    // Send response
                    std::string response = "Server received: " + message;
                    send_encrypted_message(client_socket, session, response);

                    message_counter++;

                } else if (header.type == SecureComm::MessageType::KEY_ROTATION) {
                    // Handle key rotation request. Both directions rotate together here;
                    // in-band per-direction rotation replaces this next.
                    session_manager_->rotate_rx_key(session.session_id);
                    session_manager_->rotate_tx_key(session.session_id);
                    std::cout << "Key rotation completed for session " << session.session_id << std::endl;
                    
                    // Send key rotation confirmation
                    send_key_rotation_response(client_socket, session);

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
            std::vector<uint8_t> message_data(message.begin(), message.end());
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

    void send_key_rotation_response(int client_socket, const SecureComm::SessionInfo& session) {
        SecureComm::MessageHeader header;
        header.version = SecureComm::ProtocolVersion::V1_0;
        header.type = SecureComm::MessageType::KEY_ROTATION;
        header.sequence_number = session.message_counter;
        header.timestamp = SecureComm::get_current_timestamp_seconds();
        header.payload_size = 0;
        header.flags = 0;

        std::vector<uint8_t> response_data = SecureComm::serialize_header(header);
        send_data(client_socket, response_data);
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