// Regression test for the ChatMessage envelope carried inside the ciphertext.

#include "common.h"
#include <iostream>
#include <string>

using namespace SecureComm;

static int failures = 0;

static void check(bool condition, const std::string& what) {
    if (condition) {
        std::cout << "  PASS: " << what << std::endl;
    } else {
        std::cout << "  FAIL: " << what << std::endl;
        ++failures;
    }
}

int main() {
    std::cout << "Envelope size" << std::endl;
    check(sizeof(ChatMessage) <= MAX_MESSAGE_SIZE - GCM_TAG_SIZE,
          "ChatMessage fits in one encrypted message");

    std::cout << "Round trip" << std::endl;
    ChatMessage msg = make_chat(ChatType::DIRECT);
    set_chat_field(msg.sender, MAX_NAME_LEN, "alice");
    set_chat_field(msg.recipient, MAX_NAME_LEN, "bob");
    set_chat_text(msg, "hello there");

    ChatMessage back = deserialize_chat(serialize_chat(msg));
    check(back.type == ChatType::DIRECT, "type survives round trip");
    check(get_chat_field(back.sender, MAX_NAME_LEN) == "alice", "sender survives round trip");
    check(get_chat_field(back.recipient, MAX_NAME_LEN) == "bob", "recipient survives round trip");
    check(get_chat_text(back) == "hello there", "text survives round trip");

    std::cout << "Text with embedded characters" << std::endl;
    ChatMessage punct = make_chat(ChatType::BROADCAST);
    set_chat_text(punct, "@bob is not a command here");
    check(get_chat_text(deserialize_chat(serialize_chat(punct))) == "@bob is not a command here",
          "text starting with @ is preserved verbatim");

    std::cout << "Oversized text is rejected, not truncated" << std::endl;
    ChatMessage bad = make_chat(ChatType::BROADCAST);
    bad.text_len = static_cast<uint16_t>(MAX_TEXT_LEN + 1);
    bool rejected = false;
    try {
        deserialize_chat(serialize_chat(bad));
    } catch (const std::exception&) {
        rejected = true;
    }
    check(rejected, "text_len above MAX_TEXT_LEN throws");

    std::cout << "Short buffer is rejected" << std::endl;
    rejected = false;
    try {
        deserialize_chat(std::vector<uint8_t>(4, 0));
    } catch (const std::exception&) {
        rejected = true;
    }
    check(rejected, "undersized buffer throws");

    std::cout << "Name validation" << std::endl;
    check(is_valid_name("alice"), "simple name accepted");
    check(is_valid_name("bob_2"), "underscore and digit accepted");
    check(!is_valid_name(""), "empty name rejected");
    check(!is_valid_name("has space"), "name with space rejected");
    check(!is_valid_name(std::string(MAX_NAME_LEN, 'x')), "name of MAX_NAME_LEN rejected");
    check(is_valid_name(std::string(MAX_NAME_LEN - 1, 'x')), "name of MAX_NAME_LEN-1 accepted");
    check(!is_valid_name("tab\there"), "name with tab rejected");

    std::cout << "Truncation safety" << std::endl;
    ChatMessage longname = make_chat(ChatType::DIRECT);
    set_chat_field(longname.recipient, MAX_NAME_LEN, std::string(100, 'z'));
    check(get_chat_field(longname.recipient, MAX_NAME_LEN).size() == MAX_NAME_LEN - 1,
          "over-long field is clamped and stays NUL-terminated");

    if (failures == 0) {
        std::cout << "All chat envelope tests passed" << std::endl;
        return 0;
    }
    std::cout << failures << " chat envelope test(s) failed" << std::endl;
    return 1;
}
