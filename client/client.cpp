// Terminal chat client: a console front end over SecureComm::ChatClient.

#include "chat_client.h"
#include "../crypto/crypto_utils.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

#ifndef _WIN32
    #include <signal.h>
#endif

namespace {

// Redraws the prompt so an arriving message does not corrupt a half-typed line.
void print_incoming(const std::string& line) {
    std::cout << "\r" << line << std::endl << "> " << std::flush;
}

class TerminalClient {
public:
    explicit TerminalClient(std::string room_code) : client_(make_events()), room_code_(std::move(room_code)) {}

    bool connect(const std::string& host, uint16_t port) {
        std::string error;
        if (!client_.connect(host, port, &error)) {
            std::cerr << error << std::endl;
            return false;
        }
        // People can read this out to each other to check nobody is in between.
        std::cout << "Server safety code: " << SecureComm::safety_code(client_.server_identity()) << std::endl;
        return true;
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
                  << "\n  /join room     join a room, creating it if needed"
                  << "\n  #room message  send to a room you are in"
                  << "\n  /leave room    leave a room"
                  << "\n  /rooms         list the rooms"
                  << "\n  /send to path  send a file (up to 8 MB); to is @name, #room or all"
                  << "\n  rotate         rotate your send key"
                  << "\n  quit           disconnect" << std::endl;
        std::string input;

        while (true) {
            std::cout << "> ";
            // Stop at end of input; otherwise a closed stdin spins this loop forever.
            if (!std::getline(std::cin, input)) {
                break;
            }

            if (input == "quit" || input == "exit") {
                // Replies are asynchronous, so give any still in flight a moment
                // to arrive before tearing the socket down.
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
                break;
            } else if (input == "rotate") {
                if (!client_.rotate_send_key()) {
                    std::cerr << "Key rotation failed" << std::endl;
                }
            } else if (!input.empty()) {
                if (!send_line(input)) {
                    std::cerr << "Failed to send message" << std::endl;
                    break;
                }
            }
        }
        client_.disconnect();
    }

private:
    SecureComm::ChatEvents make_events() {
        SecureComm::ChatEvents ev;
        ev.on_log = [](const std::string& line) { std::cout << line << std::endl; };
        ev.on_registered = [this](const std::string& name) {
            std::cout << "Registered as " << name << std::endl;
            answer_registration(true);
        };
        ev.on_register_failed = [this](const std::string& reason) {
            std::cout << reason << std::endl;
            answer_registration(false);
        };
        ev.on_direct = [](const std::string& from, const std::string& text) {
            print_incoming("[" + from + " -> you] " + text);
        };
        ev.on_broadcast = [](const std::string& from, const std::string& text) {
            print_incoming("[" + from + "] " + text);
        };
        ev.on_notice = [](const std::string& text) { print_incoming("*** " + text + " ***"); };
        ev.on_room_message = [](const std::string& room, const std::string& from, const std::string& text) {
            print_incoming("[#" + room + " " + from + "] " + text);
        };
        ev.on_room_event = [](const std::string& room, const std::string& name, bool joined) {
            print_incoming("*** " + name + (joined ? " joined #" : " left #") + room + " ***");
        };
        ev.on_file = [](const std::string& from, SecureComm::FileTarget, const std::string& room,
                        const std::string& name, const std::vector<uint8_t>& data) {
            // The name is the sender's choice, so it is cleaned first; and the
            // file is created only if nothing by that name exists ("x"), so a
            // received file can never replace one that is already there.
            const std::string safe = SecureComm::safe_file_name(name);
            std::error_code ec;
            const std::filesystem::path dir = "intercli-downloads";
            std::filesystem::create_directories(dir, ec);
            std::filesystem::path target = dir / safe;
            std::FILE* file = std::fopen(target.string().c_str(), "wbx");
            for (int n = 1; !file && n < 1000; ++n) {
                target = dir / (std::to_string(n) + "-" + safe);
                file = std::fopen(target.string().c_str(), "wbx");
            }
            bool out = false;
            if (file) {
                out = std::fwrite(data.data(), 1, data.size(), file) == data.size();
                out = std::fclose(file) == 0 && out;
            }
            const std::string where = room.empty() ? "" : " in #" + room;
            print_incoming(out ? "*** " + from + " sent a file" + where + ": saved as " + target.string() + " ***"
                               : "*** " + from + " sent a file" + where + ", but it could not be saved ***");
        };
        ev.on_room_list = [](const std::vector<std::string>& rooms) {
            std::string line = "Rooms (" + std::to_string(rooms.size()) + "):";
            for (const auto& room : rooms) {
                line += " #" + room;
            }
            print_incoming(line);
        };
        ev.on_presence = [](const std::string&, bool, const std::string& raw) {
            print_incoming("*** " + raw + " ***");
        };
        ev.on_roster = [](const std::vector<std::string>&, const std::string& raw) { print_incoming(raw); };
        ev.on_server_error = [](const std::string& text) {
            print_incoming("*** server error: " + text + " ***");
        };
        ev.on_send_key_rotated = [] { std::cout << "Rotated send key" << std::endl; };
        ev.on_disconnected = [this](const std::string& reason) {
            if (reason.rfind("Receive error: ", 0) == 0) {
                print_incoming("*** receive error: " + reason.substr(15) + " ***");
            } else {
                print_incoming("*** disconnected from server ***");
            }
            register_cv_.notify_all();
        };
        return ev;
    }

    void answer_registration(bool ok) {
        {
            std::lock_guard<std::mutex> lock(register_mutex_);
            register_ok_ = ok;
            register_answered_ = true;
        }
        register_cv_.notify_one();
    }

    // Prompts until the server accepts a name. The reply arrives on the receive
    // thread, so the prompt waits on a condition variable.
    bool register_name() {
        std::string name;
        while (client_.connected()) {
            std::cout << "Enter your name: " << std::flush;
            if (!std::getline(std::cin, name)) {
                return false;
            }
            if (!client_.request_name(name, room_code_)) {
                return false;
            }

            std::unique_lock<std::mutex> lock(register_mutex_);
            register_cv_.wait(lock, [this] { return register_answered_ || !client_.connected(); });
            if (!register_answered_) {
                return false;
            }
            register_answered_ = false;
            if (register_ok_) {
                return true;
            }
        }
        return false;
    }

    // A leading @ is the shorthand for a direct message; everything else broadcasts.
    bool send_line(const std::string& line) {
        if (line == "/who") {
            return client_.request_roster();
        }

        if (line.rfind("/send ", 0) == 0) {
            const size_t space = line.find(' ', 6);
            const std::string to = line.substr(6, space == std::string::npos ? std::string::npos : space - 6);
            const std::string path = space == std::string::npos ? "" : line.substr(space + 1);
            const bool to_all = to == "all";
            const bool to_room = to.size() > 1 && to[0] == '#';
            const bool to_person = to.size() > 1 && to[0] == '@';
            if (path.empty() || !(to_all || to_room || to_person)) {
                std::cout << "Usage: /send @name|#room|all path" << std::endl;
                return true;
            }
            std::ifstream in(path, std::ios::binary);
            if (!in) {
                std::cout << "Can't open " << path << std::endl;
                return true;
            }
            const std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            const auto target = to_all ? SecureComm::FileTarget::Everyone
                              : to_room ? SecureComm::FileTarget::Room : SecureComm::FileTarget::Direct;
            if (data.size() > SecureComm::MAX_FILE_SIZE ||
                !client_.send_file(target, to_all ? "" : to.substr(1), std::filesystem::path(path).filename().string(), data)) {
                std::cout << "Couldn't send the file (the limit is 8 MB)" << std::endl;
            } else {
                std::cout << "File sent" << std::endl;
            }
            return true;
        }
        if (line == "/rooms") {
            return client_.request_rooms();
        }
        const bool joining = line.rfind("/join ", 0) == 0;
        if (joining || line.rfind("/leave ", 0) == 0) {
            // "#dev" and "dev" both name the room dev.
            std::string room = line.substr(joining ? 6 : 7);
            if (!room.empty() && room[0] == '#') {
                room.erase(0, 1);
            }
            if (!SecureComm::is_valid_name(room)) {
                std::cout << "Room names are 1-31 characters with no spaces" << std::endl;
                return true;
            }
            return joining ? client_.join_room(room) : client_.leave_room(room);
        }
        if (line.rfind("#", 0) == 0) {
            const size_t space = line.find(' ');
            if (space == std::string::npos || space == 1 || !SecureComm::is_valid_name(line.substr(1, space - 1))) {
                std::cout << "Usage: #room message" << std::endl;
                return true;
            }
            const std::string body = line.substr(space + 1);
            if (body.size() > SecureComm::MAX_TEXT_LEN) {
                std::cout << "Message too long (max " << SecureComm::MAX_TEXT_LEN << " bytes)" << std::endl;
                return true;
            }
            return client_.send_room(line.substr(1, space - 1), body);
        }
        const bool direct = line.rfind("@", 0) == 0;
        std::string to;
        std::string text = line;
        if (direct) {
            const size_t space = line.find(' ');
            if (space == std::string::npos || space == 1) {
                std::cout << "Usage: @name message" << std::endl;
                return true;
            }
            to = line.substr(1, space - 1);
            text = line.substr(space + 1);
        }

        if (text.size() > SecureComm::MAX_TEXT_LEN) {
            std::cout << "Message too long (max " << SecureComm::MAX_TEXT_LEN << " bytes)" << std::endl;
            return true;
        }
        return direct ? client_.send_direct(to, text) : client_.send_broadcast(text);
    }

    SecureComm::ChatClient client_;
    std::string room_code_;
    std::mutex register_mutex_;
    std::condition_variable register_cv_;
    bool register_answered_ = false;
    bool register_ok_ = false;
};

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <server_ip> [port]" << std::endl;
        std::cout << "Example: " << argv[0] << " 127.0.0.1 8080" << std::endl;
        std::cout << "For a chat with a room code, set INTERCLI_ROOM_CODE first" << std::endl;
        std::cout << "(not on the command line, where other programs could see it)." << std::endl;
        return 1;
    }

#ifndef _WIN32
    // Sending after the server has gone raises SIGPIPE, which would kill the client
    // instead of letting the failed send be reported.
    signal(SIGPIPE, SIG_IGN);
#endif

    const std::string server_ip = argv[1];

    try {
        // Inside the try: std::stoi throws on a non-numeric port.
        const int port_number = (argc > 2) ? std::stoi(argv[2]) : SecureComm::DEFAULT_PORT;
        if (port_number < 1 || port_number > 65535) {
            std::cerr << "The port must be a number from 1 to 65535" << std::endl;
            return 1;
        }
        const uint16_t port = static_cast<uint16_t>(port_number);
        const char* room_code = std::getenv("INTERCLI_ROOM_CODE");
        TerminalClient client(room_code ? room_code : "");

        if (!client.connect(server_ip, port)) {
            std::cerr << "Failed to connect to server" << std::endl;
            return 1;
        }

        std::cout << "Secure Communication Client" << std::endl;
        std::cout << "Features:" << std::endl;
        std::cout << "- Diffie-Hellman key exchange (new keys for every connection)" << std::endl;
        std::cout << "- Server identity proven with an Ed25519 signature" << std::endl;
        std::cout << "- AES-256-GCM encryption, with altered or replayed messages rejected" << std::endl;
        std::cout << "- Manual key rotation" << std::endl;

        client.interactive_mode();

    } catch (const std::exception& e) {
        std::cerr << "Client error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
