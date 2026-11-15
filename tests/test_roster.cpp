// Unit test for parsing the server's /who reply.

#include "chat_client.h"
#include <iostream>
#include <string>
#include <vector>

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
    std::cout << "Roster parsing" << std::endl;
    check(parse_roster("Online (3): alice, bob, carol") ==
              std::vector<std::string>{"alice", "bob", "carol"},
          "three names are split on comma-space");
    check(parse_roster("Online (1): a,b") == std::vector<std::string>{"a,b"},
          "a comma inside a name is kept");
    check(parse_roster("Online (0): ").empty(), "empty roster gives no names");
    check(parse_roster("garbage").empty(), "malformed text gives no names");

    if (failures == 0) {
        std::cout << "All roster tests passed" << std::endl;
        return 0;
    }
    std::cout << failures << " roster test(s) failed" << std::endl;
    return 1;
}
