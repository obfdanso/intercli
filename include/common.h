#pragma once

// Undefine OpenSSL ERROR macro if it exists to avoid conflicts
#ifdef ERROR
#undef ERROR
#endif

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <chrono>
#include <random>
#include <mutex>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/aes.h>

namespace SecureComm {

// Protocol constants
constexpr uint16_t DEFAULT_PORT = 8080;
constexpr size_t MAX_MESSAGE_SIZE = 4096;
constexpr size_t KEY_SIZE = 32;
constexpr size_t IV_SIZE = 12;
constexpr size_t HASH_SIZE = 32;
constexpr size_t SIGNATURE_SIZE = 256;
constexpr size_t HMAC_SIZE = 32;
constexpr size_t GCM_TAG_SIZE = 16;
constexpr size_t MAX_PUBLIC_KEY_SIZE = 2048;
constexpr size_t MAX_NAME_LEN = 32;
constexpr size_t MAX_TEXT_LEN = 1024;
constexpr size_t MAX_FRAME_SIZE = 65536;
constexpr size_t MAX_FILE_SIZE = 8 * 1024 * 1024;
constexpr size_t FILE_CHUNK_HEADER = 17;
constexpr size_t FILE_CHUNK_DATA = MAX_TEXT_LEN - FILE_CHUNK_HEADER;
constexpr size_t MAX_FILE_NAME_LEN = 255;
// End-to-end encryption of direct messages: the sender's X25519 public key
// travels with each one, and sealing adds a nonce and a tag.
constexpr size_t E2E_KEY_SIZE = 32;
constexpr size_t E2E_SEAL_OVERHEAD = IV_SIZE + GCM_TAG_SIZE;
constexpr size_t MAX_DIRECT_TEXT = MAX_TEXT_LEN - E2E_KEY_SIZE - E2E_SEAL_OVERHEAD;
// Each peer rotates the key it sends with after this many messages sent.
constexpr uint32_t KEY_ROTATION_INTERVAL = 10;

// Message types
enum class MessageType : uint8_t {
    HANDSHAKE_INIT = 0x01,
    HANDSHAKE_RESPONSE = 0x02,
    HANDSHAKE_COMPLETE = 0x03,
    ENCRYPTED_MESSAGE = 0x04,
    KEY_ROTATION = 0x05,
    AUTHENTICATION = 0x06,
    ERROR_MESSAGE = 0xFF
};

// Protocol versions
enum class ProtocolVersion : uint8_t {
    V1_0 = 0x01,
    // Version 2: the server signs the handshake with its identity key, every
    // encrypted frame binds its header into AES-GCM and must arrive in sequence,
    // and key rotations are encrypted frames.
    V2_0 = 0x02
};

constexpr ProtocolVersion PROTOCOL_VERSION = ProtocolVersion::V2_0;
constexpr size_t IDENTITY_KEY_SIZE = 32;        // Ed25519 public key
constexpr size_t IDENTITY_SIGNATURE_SIZE = 64;  // Ed25519 signature
constexpr char ROTATION_MARKER[] = "ROTATE";

// Forward secrecy types
enum class ForwardSecrecyType : uint8_t {
    NONE = 0x00,
    DH = 0x01,
    ECDH = 0x02,
    PERFECT_FORWARD_SECRECY = 0x03
};

// Chat envelope types, carried inside the encrypted payload
enum class ChatType : uint8_t {
    REGISTER      = 0x01,
    REGISTER_OK   = 0x02,
    REGISTER_FAIL = 0x03,
    DIRECT        = 0x04,
    BROADCAST     = 0x05,
    WHO           = 0x06,
    ROSTER        = 0x07,
    PRESENCE      = 0x08,
    NOTICE        = 0x09,
    // Named rooms. The room's name travels in the recipient field.
    ROOM_JOIN     = 0x0A,  // client: join the room, creating it if needed
    ROOM_LEAVE    = 0x0B,  // client: leave the room
    ROOM_MESSAGE  = 0x0C,  // a message to the room's members
    ROOM_EVENT    = 0x0D,  // server: sender joined or left (text "joined" / "left")
    ROOM_LIST     = 0x0E,  // client asks; server answers "a, b, c"
    // One piece of a file. The text is binary: kind ('d' direct, 'e' everyone,
    // 'r' room), an 8-byte transfer id, then the piece number and the number
    // of pieces (4 bytes each, little-endian). Piece 0 carries the size
    // (8 bytes) and the file name; the rest carry the bytes in order.
    FILE_CHUNK    = 0x0F,
    // What became of direct messages. From the server, about the person in the
    // sender field: "delivered", or "queued" (they are away; kept for them).
    // From a client, to the person in the recipient field: "read".
    RECEIPT       = 0x10,
    // People's public keys for end-to-end encryption. A client asks for the
    // key of the person in the recipient field; the server answers with that
    // person in the sender field and the key as the text (empty: no key).
    KEY           = 0x11,
};

// The four structs below travel on the wire as raw bytes, so every compiler
// must lay them out identically: without packing, GCC and Clang add padding
// that MSVC builds do not, and the two cannot talk to each other.
#pragma pack(push, 1)

// Message header structure
struct MessageHeader {
    ProtocolVersion version;
    MessageType type;
    uint32_t sequence_number;
    uint32_t timestamp;
    uint16_t payload_size;
    uint16_t flags;
};

// Handshake message structure
// public_key holds a PEM-encoded key, which is far larger than a symmetric
// KEY_SIZE key, so it carries its own length rather than being truncated.
struct HandshakeMessage {
    uint32_t client_id;
    uint32_t session_id;
    ForwardSecrecyType fs_type;
    uint16_t public_key_len;
    uint8_t public_key[MAX_PUBLIC_KEY_SIZE];
    uint8_t nonce[IV_SIZE];
};

// Chat message envelope. Travels inside the AES-GCM ciphertext, so the server
// can route on it while the network sees only ciphertext.
struct ChatMessage {
    ChatType type;
    char     sender[MAX_NAME_LEN];
    char     recipient[MAX_NAME_LEN];
    uint16_t text_len;
    char     text[MAX_TEXT_LEN];
};

// Encrypted message structure
struct EncryptedMessage {
    uint32_t session_id;
    uint32_t message_id;
    uint8_t iv[IV_SIZE];
    uint8_t encrypted_data[MAX_MESSAGE_SIZE];
};

#pragma pack(pop)

// Session information
struct SessionInfo {
    uint32_t session_id;
    uint32_t client_id;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_activity;
    std::vector<uint8_t> shared_secret;
    std::vector<uint8_t> tx_key;
    std::vector<uint8_t> rx_key;
    uint32_t message_counter;
    bool authenticated;
    bool key_rotated;
};

// Key pair structure
struct KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
};

// Authentication result
enum class AuthResult {
    SUCCESS,
    INVALID_SIGNATURE,
    EXPIRED_SESSION,
    INVALID_KEY,
    UNKNOWN_CLIENT
};

// Error codes
enum class ErrorCode : uint16_t {
    NONE = 0x0000,
    INVALID_MESSAGE = 0x0001,
    AUTHENTICATION_FAILED = 0x0002,
    SESSION_EXPIRED = 0x0003,
    KEY_ROTATION_FAILED = 0x0004,
    ENCRYPTION_FAILED = 0x0005,
    DECRYPTION_FAILED = 0x0006,
    INVALID_PROTOCOL_VERSION = 0x0007,
    INTERNAL_ERROR = 0x00FF
};

// Utility functions
inline std::string error_code_to_string(ErrorCode code) {
    switch (code) {
        case ErrorCode::NONE: return "None";
        case ErrorCode::INVALID_MESSAGE: return "Invalid Message";
        case ErrorCode::AUTHENTICATION_FAILED: return "Authentication Failed";
        case ErrorCode::SESSION_EXPIRED: return "Session Expired";
        case ErrorCode::KEY_ROTATION_FAILED: return "Key Rotation Failed";
        case ErrorCode::ENCRYPTION_FAILED: return "Encryption Failed";
        case ErrorCode::DECRYPTION_FAILED: return "Decryption Failed";
        case ErrorCode::INVALID_PROTOCOL_VERSION: return "Invalid Protocol Version";
        case ErrorCode::INTERNAL_ERROR: return "Internal Error";
        default: return "Unknown Error";
    }
}

inline std::string message_type_to_string(MessageType type) {
    switch (type) {
        case MessageType::HANDSHAKE_INIT: return "Handshake Init";
        case MessageType::HANDSHAKE_RESPONSE: return "Handshake Response";
        case MessageType::HANDSHAKE_COMPLETE: return "Handshake Complete";
        case MessageType::ENCRYPTED_MESSAGE: return "Encrypted Message";
        case MessageType::KEY_ROTATION: return "Key Rotation";
        case MessageType::AUTHENTICATION: return "Authentication";
        case MessageType::ERROR_MESSAGE: return "Error";
        default: return "Unknown";
    }
}

inline std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

inline uint32_t generate_session_id() {
    thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<unsigned int> dis(1, 0xFFFFFFFF);
    return static_cast<uint32_t>(dis(gen));
}

inline uint32_t generate_client_id() {
    thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<unsigned int> dis(1, 0xFFFFFFFF);
    return static_cast<uint32_t>(dis(gen));
}

inline std::vector<uint8_t> generate_nonce(size_t size) {
    thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<unsigned int> dis(0, 255);
    
    std::vector<uint8_t> nonce(size);
    for (size_t i = 0; i < size; ++i) {
        nonce[i] = static_cast<uint8_t>(dis(gen));
    }
    return nonce;
}

inline std::chrono::system_clock::time_point get_current_timestamp() {
    return std::chrono::system_clock::now();
}

inline uint32_t get_current_timestamp_seconds() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    return static_cast<uint32_t>(seconds.count());
}

// Serialization helpers
inline std::vector<uint8_t> serialize_header(const MessageHeader& header) {
    std::vector<uint8_t> data(sizeof(MessageHeader));
    std::memcpy(data.data(), &header, sizeof(MessageHeader));
    return data;
}

inline MessageHeader deserialize_header(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(MessageHeader)) {
        throw std::runtime_error("Invalid header data size");
    }
    MessageHeader header;
    std::memcpy(&header, data.data(), sizeof(MessageHeader));
    return header;
}

inline std::vector<uint8_t> serialize_handshake(const HandshakeMessage& handshake) {
    std::vector<uint8_t> data(sizeof(HandshakeMessage));
    std::memcpy(data.data(), &handshake, sizeof(HandshakeMessage));
    return data;
}

inline HandshakeMessage deserialize_handshake(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(HandshakeMessage)) {
        throw std::runtime_error("Invalid handshake data size");
    }
    HandshakeMessage handshake;
    std::memcpy(&handshake, data.data(), sizeof(HandshakeMessage));
    return handshake;
}

inline std::vector<uint8_t> serialize_encrypted_message(const EncryptedMessage& msg) {
    std::vector<uint8_t> data(sizeof(EncryptedMessage));
    std::memcpy(data.data(), &msg, sizeof(EncryptedMessage));
    return data;
}

inline EncryptedMessage deserialize_encrypted_message(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(EncryptedMessage)) {
        throw std::runtime_error("Invalid encrypted message data size");
    }
    EncryptedMessage msg;
    std::memcpy(&msg, data.data(), sizeof(EncryptedMessage));
    return msg;
}

inline ChatMessage make_chat(ChatType type) {
    ChatMessage msg{};
    msg.type = type;
    msg.text_len = 0;
    return msg;
}

inline void set_chat_field(char* field, size_t field_size, const std::string& value) {
    std::memset(field, 0, field_size);
    const size_t copy_len = std::min(value.size(), field_size - 1);
    std::memcpy(field, value.data(), copy_len);
}

inline std::string get_chat_field(const char* field, size_t field_size) {
    size_t len = 0;
    while (len < field_size && field[len] != '\0') {
        ++len;
    }
    return std::string(field, len);
}

inline void set_chat_text(ChatMessage& msg, const std::string& text) {
    const size_t copy_len = std::min(text.size(), MAX_TEXT_LEN);
    std::memset(msg.text, 0, MAX_TEXT_LEN);
    std::memcpy(msg.text, text.data(), copy_len);
    msg.text_len = static_cast<uint16_t>(copy_len);
}

inline std::string get_chat_text(const ChatMessage& msg) {
    if (msg.text_len > MAX_TEXT_LEN) {
        throw std::runtime_error("Chat text_len out of range");
    }
    return std::string(msg.text, msg.text_len);
}

// Printable ASCII excluding space: 0x21 to 0x7E rules out control characters,
// space and tab in one check, keeping names typeable in the @name shorthand.
inline bool is_valid_name(const std::string& name) {
    if (name.empty() || name.size() >= MAX_NAME_LEN) {
        return false;
    }
    // A leading # marks a room wherever people and rooms are listed together.
    if (name[0] == '#') {
        return false;
    }
    for (unsigned char c : name) {
        if (c < 0x21 || c > 0x7E) {
            return false;
        }
    }
    return true;
}

inline std::vector<uint8_t> serialize_chat(const ChatMessage& msg) {
    std::vector<uint8_t> data(sizeof(ChatMessage));
    std::memcpy(data.data(), &msg, sizeof(ChatMessage));
    return data;
}

inline ChatMessage deserialize_chat(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(ChatMessage)) {
        throw std::runtime_error("Invalid chat message size");
    }
    ChatMessage msg;
    std::memcpy(&msg, data.data(), sizeof(ChatMessage));
    if (msg.text_len > MAX_TEXT_LEN) {
        throw std::runtime_error("Chat text_len out of range");
    }
    return msg;
}

// A file name chosen by someone else, made safe to create inside a folder of
// ours: no folders, no characters Windows refuses, no trailing dots or spaces,
// and never one of Windows' device names (CON, NUL, COM1...), which would open
// the device instead of a file.
inline std::string safe_file_name(const std::string& name) {
    const size_t slash = name.find_last_of("/\\");
    std::string safe = slash == std::string::npos ? name : name.substr(slash + 1);
    for (char& c : safe) {
        if (static_cast<unsigned char>(c) < 0x20 || std::strchr(":*?\"<>|", c) != nullptr) {
            c = '_';
        }
    }
    while (!safe.empty() && (safe.back() == '.' || safe.back() == ' ')) {
        safe.pop_back();
    }
    while (!safe.empty() && safe.front() == ' ') {
        safe.erase(0, 1);
    }
    if (safe.empty()) {
        return "file";  // also what "." and ".." come to
    }
    std::string base = safe.substr(0, safe.find('.'));
    while (!base.empty() && base.back() == ' ') {
        base.pop_back();
    }
    for (char& c : base) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    const bool numbered_port = (base.rfind("COM", 0) == 0 || base.rfind("LPT", 0) == 0) && base.size() >= 4 &&
                               base.size() <= 6 && !std::isalpha(static_cast<unsigned char>(base[3]));
    if (base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" ||
        base == "CONOUT$" || numbered_port) {
        safe.insert(safe.begin(), '_');
    }
    return safe;
}

// What AES-GCM authenticates alongside every encrypted frame: the protocol
// version, frame type, sequence number and session. Changing, replaying or
// reordering a frame makes decryption fail.
inline std::vector<uint8_t> frame_aad(MessageType type, uint32_t sequence, uint32_t session_id) {
    std::vector<uint8_t> aad;
    aad.push_back(static_cast<uint8_t>(PROTOCOL_VERSION));
    aad.push_back(static_cast<uint8_t>(type));
    for (int i = 0; i < 4; ++i) aad.push_back(static_cast<uint8_t>(sequence >> (8 * i)));
    for (int i = 0; i < 4; ++i) aad.push_back(static_cast<uint8_t>(session_id >> (8 * i)));
    return aad;
}

// What the server signs in its handshake response, so the client knows the DH
// keys and nonces it is about to use came from the server's identity key.
inline std::vector<uint8_t> handshake_transcript(uint32_t session_id,
                                                 const std::vector<uint8_t>& client_key,
                                                 const std::vector<uint8_t>& client_nonce,
                                                 const std::vector<uint8_t>& server_key,
                                                 const std::vector<uint8_t>& server_nonce) {
    const std::string label = "intercli-handshake-v2";
    std::vector<uint8_t> t(label.begin(), label.end());
    for (int i = 0; i < 4; ++i) t.push_back(static_cast<uint8_t>(session_id >> (8 * i)));
    auto add = [&t](const std::vector<uint8_t>& v) {
        t.push_back(static_cast<uint8_t>(v.size()));
        t.push_back(static_cast<uint8_t>(v.size() >> 8));
        t.insert(t.end(), v.begin(), v.end());
    };
    add(client_key);
    add(client_nonce);
    add(server_key);
    add(server_nonce);
    return t;
}

} // namespace SecureComm
 