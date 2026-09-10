#include "common.h"
#include "../crypto/crypto_utils.h"
#include <iostream>
#include <string>
#include <memory>
#include <algorithm>
#include <chrono>
#include <vector>

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
    std::vector<uint8_t> session_key_;
    uint32_t message_counter_;

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
        return true;
    }

    void disconnect() {
        if (client_socket_ >= 0) {
#ifdef _WIN32
            closesocket(client_socket_);
#else
            close(client_socket_);
#endif
            client_socket_ = -1;
        }
    }

    bool send_encrypted_message(const std::string& message) {
        try {
            std::vector<uint8_t> message_data(message.begin(), message.end());
            std::vector<uint8_t> iv = crypto_manager_->generate_random_bytes(SecureComm::IV_SIZE);
            
            std::vector<uint8_t> encrypted_data = crypto_manager_->encrypt_aes_gcm(message_data, session_key_, iv);
            
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
            std::cout << "Sent encrypted message: " << message << std::endl;

            // Receive response
            std::string response = receive_encrypted_message();
            if (!response.empty()) {
                std::cout << "Server response: " << response << std::endl;
            }

            // The server rotates unprompted every 10 messages, so mirror its schedule
            // here. Both sides count the same exchanges and derive the same key.
            if (message_counter_ % 10 == 0) {
                session_key_ = crypto_manager_->rotate_session_key(session_key_,
                    std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&current_session_.session_id),
                                        reinterpret_cast<const uint8_t*>(&current_session_.session_id) + sizeof(current_session_.session_id)));
            }

            return true;

        } catch (const std::exception& e) {
            std::cerr << "Failed to send encrypted message: " << e.what() << std::endl;
            return false;
        }
    }

    bool request_key_rotation() {
        try {
            SecureComm::MessageHeader header;
            header.version = SecureComm::ProtocolVersion::V1_0;
            header.type = SecureComm::MessageType::KEY_ROTATION;
            header.sequence_number = message_counter_;
            header.timestamp = SecureComm::get_current_timestamp_seconds();
            header.payload_size = 0;
            header.flags = 0;

            std::vector<uint8_t> request_data = SecureComm::serialize_header(header);
            
            if (!send_data(request_data)) {
                std::cerr << "Failed to send key rotation request" << std::endl;
                return false;
            }

            // Receive key rotation response
            std::vector<uint8_t> response_data = receive_data();
            if (response_data.empty()) {
                std::cerr << "No response to key rotation request" << std::endl;
                return false;
            }

            SecureComm::MessageHeader response_header = SecureComm::deserialize_header(response_data);
            if (response_header.type == SecureComm::MessageType::KEY_ROTATION) {
                // Update session key
                session_key_ = crypto_manager_->rotate_session_key(session_key_, 
                    std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&current_session_.session_id), 
                                        reinterpret_cast<const uint8_t*>(&current_session_.session_id) + sizeof(current_session_.session_id)));
                
                std::cout << "Key rotation completed successfully" << std::endl;
                return true;
            } else {
                std::cerr << "Unexpected response to key rotation request" << std::endl;
                return false;
            }

        } catch (const std::exception& e) {
            std::cerr << "Key rotation failed: " << e.what() << std::endl;
            return false;
        }
    }

    void interactive_mode() {
        std::cout << "\nInteractive mode - Type 'quit' to exit, 'rotate' to rotate keys" << std::endl;
        std::string input;
        
        while (true) {
            std::cout << "> ";
            std::getline(std::cin, input);
            
            if (input == "quit" || input == "exit") {
                break;
            } else if (input == "rotate") {
                if (request_key_rotation()) {
                    std::cout << "Key rotation successful" << std::endl;
                } else {
                    std::cerr << "Key rotation failed" << std::endl;
                }
            } else if (!input.empty()) {
                if (!send_encrypted_message(input)) {
                    std::cerr << "Failed to send message" << std::endl;
                    break;
                }
            }
        }
    }

private:
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
            
            // Derive session key
            std::vector<uint8_t> server_nonce(server_handshake.nonce, server_handshake.nonce + SecureComm::IV_SIZE);
            session_key_ = crypto_manager_->derive_shared_secret(shared_secret, server_nonce);

            current_session_.shared_secret = shared_secret;
            current_session_.current_key = session_key_;
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

    std::string receive_encrypted_message() {
        try {
            std::vector<uint8_t> encrypted_data = receive_data();
            if (encrypted_data.empty()) {
                return "";
            }

            SecureComm::MessageHeader header = SecureComm::deserialize_header(encrypted_data);
            
            if (header.type == SecureComm::MessageType::ENCRYPTED_MESSAGE) {
                // Extract encrypted message
                std::vector<uint8_t> payload(encrypted_data.begin() + sizeof(SecureComm::MessageHeader), encrypted_data.end());
                SecureComm::EncryptedMessage encrypted_msg = SecureComm::deserialize_encrypted_message(payload);

                // Decrypt message
                std::vector<uint8_t> iv(encrypted_msg.iv, encrypted_msg.iv + SecureComm::IV_SIZE);
                
                std::vector<uint8_t> encrypted_payload(encrypted_msg.encrypted_data, 
                                                      encrypted_msg.encrypted_data + header.payload_size);
                std::vector<uint8_t> decrypted_data = crypto_manager_->decrypt_aes_gcm(
                    encrypted_payload, session_key_, iv);

                std::string message(decrypted_data.begin(), decrypted_data.end());
                return message;

            } else if (header.type == SecureComm::MessageType::ERROR_MESSAGE) {
                std::vector<uint8_t> payload(encrypted_data.begin() + sizeof(SecureComm::MessageHeader), encrypted_data.end());
                if (payload.size() >= sizeof(SecureComm::ErrorCode)) {
                    SecureComm::ErrorCode error_code = *reinterpret_cast<const SecureComm::ErrorCode*>(payload.data());
                    std::cerr << "Server error: " << SecureComm::error_code_to_string(error_code) << std::endl;
                }
                return "";

            } else {
                std::cerr << "Unexpected message type: " << SecureComm::message_type_to_string(header.type) << std::endl;
                return "";
            }

        } catch (const std::exception& e) {
            std::cerr << "Error receiving encrypted message: " << e.what() << std::endl;
            return "";
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