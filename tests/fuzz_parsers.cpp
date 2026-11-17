// Feeds random bytes to everything that reads what another machine sent.
// Built only with -DINTERCLI_FUZZ=ON (clang): see the Fuzzing part of the readme.

#include "chat_client.h"
#include "common.h"
#include "crypto_utils.h"

#include <cstdint>
#include <string>
#include <vector>

using namespace SecureComm;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::vector<uint8_t> bytes(data, data + size);
    const std::string text(reinterpret_cast<const char*>(data), size);

    try { deserialize_header(bytes); } catch (const std::exception&) {}
    try { deserialize_handshake(bytes); } catch (const std::exception&) {}
    try { deserialize_encrypted_message(bytes); } catch (const std::exception&) {}
    try {
        const ChatMessage chat = deserialize_chat(bytes);
        get_chat_text(chat);
        is_valid_name(get_chat_field(chat.sender, MAX_NAME_LEN));
        get_chat_field(chat.recipient, MAX_NAME_LEN);
    } catch (const std::exception&) {}

    is_valid_name(text);
    safe_file_name(text);
    parse_roster(text);
    normalize_room_code(text);
    format_room_code(text);
    try { hex_to_bytes(text); } catch (const std::exception&) {}
    return 0;
}
