#pragma once

// The chat client without any console or UI: connects, runs the secure
// handshake, sends chat messages and reports everything that arrives through
// callbacks. The terminal client and the desktop app are both front ends over it.

#include "common.h"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace SecureComm {

class CryptoManager;

// Where a file goes, or came in from.
enum class FileTarget { Direct, Everyone, Room };

// Every callback runs on the client's receive thread, except on_send_key_rotated,
// which runs on whichever thread sent the message that triggered the rotation.
// A callback may call disconnect(), but must not destroy the ChatClient.
struct ChatEvents {
    std::function<void(const std::string& name)> on_registered;
    std::function<void(const std::string& reason)> on_register_failed;
    std::function<void(const std::string& from, const std::string& text)> on_direct;
    std::function<void(const std::string& from, const std::string& text)> on_broadcast;
    std::function<void(const std::vector<std::string>& names, const std::string& raw)> on_roster;
    std::function<void(const std::string& name, bool joined, const std::string& raw)> on_presence;
    // Named rooms: a message to a room we are in; someone (maybe us) joining
    // or leaving one; and the answer to request_rooms().
    std::function<void(const std::string& room, const std::string& from, const std::string& text)> on_room_message;
    std::function<void(const std::string& room, const std::string& name, bool joined)> on_room_event;
    std::function<void(const std::vector<std::string>& rooms)> on_room_list;
    // A whole file has arrived. room is set for FileTarget::Room. name is
    // whatever the sender chose: clean it before using it as a file name.
    std::function<void(const std::string& from, FileTarget target, const std::string& room,
                       const std::string& name, const std::vector<uint8_t>& data)> on_file;
    std::function<void(const std::string& text)> on_notice;
    std::function<void(const std::string& text)> on_server_error;
    std::function<void()> on_send_key_rotated;
    std::function<void()> on_receive_key_rotated;
    // Fired once when a connection is lost; never after a disconnect() call.
    std::function<void(const std::string& reason)> on_disconnected;
    std::function<void(const std::string& line)> on_log;
};

struct SessionStatus {
    bool connected = false;
    std::string cipher = "AES-256-GCM";
    std::string key_exchange = "Diffie-Hellman (ffdhe2048)";
    uint32_t send_rotations = 0;
    uint32_t receive_rotations = 0;
    uint32_t messages_until_rotation = KEY_ROTATION_INTERVAL;
    std::optional<std::chrono::system_clock::time_point> last_send_rotation;
};

class ChatClient {
public:
    explicit ChatClient(ChatEvents events);
    ~ChatClient();

    ChatClient(const ChatClient&) = delete;
    ChatClient& operator=(const ChatClient&) = delete;

    // The server identity key this chat is known to have (from an earlier
    // join). If set, connect() refuses a server that proves a different one,
    // before anything else is sent. Empty: accept any identity.
    void set_expected_identity(std::vector<uint8_t> public_raw);
    // The identity key the server proved in the last handshake (also when it
    // was refused for not matching the expected one).
    std::vector<uint8_t> server_identity() const;

    // Blocking: resolves the host, connects, runs the handshake and starts the
    // receive thread. On failure returns false and, if error is given, a reason.
    bool connect(const std::string& host, uint16_t port, std::string* error);

    // Safe from another thread or inside a callback, but not at the same time as
    // connect() on another thread: use cancel() for that.
    void disconnect();

    // Makes a connect() running on another thread give up within about 100 ms.
    // Safe from any thread. A cancelled client cannot connect again.
    void cancel();

    // The server's answer arrives through on_registered or on_register_failed.
    // room_code is needed for a hosted chat; it is ignored by an open server.
    bool request_name(const std::string& name, const std::string& room_code = "");

    // Text over MAX_TEXT_LEN bytes is rejected (returns false, nothing is sent).
    bool send_direct(const std::string& to, const std::string& text);
    bool send_broadcast(const std::string& text);
    bool request_roster();

    // Named rooms. Joining a room that doesn't exist creates it; our own
    // on_room_event (joined) is the confirmation. A problem comes as a notice.
    bool join_room(const std::string& room);
    bool leave_room(const std::string& room);
    bool send_room(const std::string& room, const std::string& text);
    bool request_rooms();

    // Sends a file of up to MAX_FILE_SIZE bytes in pieces. Blocking, so call it
    // off the UI thread; other messages can be sent meanwhile. to is the
    // person or room (unused for Everyone). False if it is too big, the name
    // is empty or over 255 bytes, or the connection fails part-way.
    bool send_file(FileTarget target, const std::string& to, const std::string& name,
                   const std::vector<uint8_t>& data);
    bool rotate_send_key();

    bool connected() const;
    // Whether TCP keepalive probes are on for the current connection.
    bool keepalive_enabled() const;
    SessionStatus status() const;

    // Test only: drops the connection as if the network failed, so
    // on_disconnected fires.
    void drop_connection_for_test();
    // Test only: reports a receive error the way a bad frame would, leaving
    // the socket itself open.
    void fail_receive_for_test();

private:
    // quiet: don't report key rotations (a file would report hundreds).
    bool send_chat(const ChatMessage& chat, bool quiet = false);
    void handle_file_chunk(const ChatMessage& msg, const std::string& from, const std::string& body);
    bool rotate_locked();
    std::vector<uint8_t> seal_frame(MessageType type, const std::vector<uint8_t>& plain);
    bool open_frame(const std::vector<uint8_t>& frame, std::vector<uint8_t>* plain);
    bool perform_handshake(std::string* error);
    bool connect_socket(const std::string& host, uint16_t port, std::string* error);
    void set_receive_timeout(int ms);
    void receive_loop();
    void dispatch_frame(const std::vector<uint8_t>& data);
    void handle_chat(const ChatMessage& msg);
    void report_lost(const std::string& reason);
    void log(const std::string& line);
    void close_socket();
    std::vector<uint8_t> session_id_bytes() const;

    bool receive_all(uint8_t* data, size_t length);
    std::vector<uint8_t> receive_data();
    bool send_all(const uint8_t* data, size_t length);
    bool send_data(const std::vector<uint8_t>& data);

    ChatEvents events_;
    std::unique_ptr<CryptoManager> crypto_;
    KeyPair dh_keypair_;
    SessionInfo session_;

    std::atomic<intptr_t> socket_{-1};
    std::thread receive_thread_;
    std::atomic<bool> connected_{false};
    std::atomic<bool> user_disconnect_{false};
    std::atomic<bool> cancelled_{false};

    // Guards everything a send touches: the counter, the tx key and the socket writes.
    mutable std::mutex send_mutex_;
    std::vector<uint8_t> tx_key_;
    uint32_t message_counter_ = 0;
    uint32_t tx_seq_ = 0;  // last frame number sent
    uint32_t send_rotations_ = 0;
    std::optional<std::chrono::system_clock::time_point> last_send_rotation_;

    // Guards the rx key, which the receive thread rotates.
    mutable std::mutex rx_mutex_;
    std::vector<uint8_t> rx_key_;
    uint32_t receive_rotations_ = 0;
    uint32_t rx_seq_ = 0;  // last frame number received; receive thread only

    // Files being received, by sender and transfer id; receive thread only.
    struct IncomingFile {
        char kind = 'd';
        std::string room;
        std::string name;
        uint64_t size = 0;
        uint32_t total = 0;
        uint32_t next = 1;
        std::vector<uint8_t> data;
    };
    std::map<std::string, IncomingFile> incoming_files_;

    std::vector<uint8_t> expected_identity_;
    std::vector<uint8_t> server_identity_;
};

// Parses the server's "Online (N): a, b, c" reply. Names never contain spaces,
// so ", " separates them unambiguously. Malformed text gives an empty list.
std::vector<std::string> parse_roster(const std::string& text);

} // namespace SecureComm
